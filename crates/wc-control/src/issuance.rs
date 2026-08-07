//! Contract issuance: request → approval → mint (`docs/08-lld.md` §8.7.2, UC-04).
//!
//! The core loop. A developer asks for a connection; policy either issues it under
//! standing rules or routes it to a named human; a mint produces one signed
//! artifact per mediator on the path.
//!
//! # Three properties this module exists to hold
//!
//! **An approval is a signed artifact, not a database row.** The approver signs a
//! digest of exactly the request they were shown. Mutate the request afterwards and
//! the signature stops matching — so an operator with write access to the store
//! cannot widen a surface a human already approved.
//!
//! **An approval goes stale.** It records the policy version in force when it was
//! given. If policy moves before the mint, the approval is refused
//! ([`Code::APPROVAL_STALE`]) rather than applied under rules nobody agreed to.
//!
//! **Nothing is minted without a durable trail.** Blocking evidence sinks are
//! shipped before the artifact is signed, so authority never exists without a
//! record of its creation (§7.8).

use serde::{Deserialize, Serialize};

use wc_core::contract::{
    self, ApprovalMode, ApprovalRef, Assurance, ContractPayload, ContractRecord, ContractStatus,
    IssuerKey, IssuerKeys, Party, Surface, Terms, CONTRACT_SCHEMA,
};
use wc_core::error::{Code, Mode, Result, WcError};
use wc_core::model::{Cid, Entity, EntityId, HumanRef, Jti, Lifecycle, Posture};
use wc_core::util::{canonical_json, sha256_hex};

use crate::cpolicy::{ConnDecision, ConnEval, ConnRequest, ConnectPolicy, StandingState};
use crate::evidence::{EventKind, Evidence, LifecycleEvent};
use crate::store::{Actor, Durability, Event, Store};

/// How long a pending request waits for a human before it lapses.
///
/// Silence terminates; it never approves (UC-04 A3).
pub const DEFAULT_REQUEST_TTL_SECS: u64 = 72 * 3_600;

// ---------------------------------------------------------------------------
// Pending requests
// ---------------------------------------------------------------------------

/// Where a request has got to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestStatus {
    /// Waiting for a human.
    Pending,
    /// Approved and minted.
    Minted,
    /// Refused by a human.
    Denied,
    /// Nobody answered in time.
    Lapsed,
}

/// A connection request awaiting a decision.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PendingRequest {
    /// Request id, `req_…`.
    pub id: String,
    /// Calling party.
    pub caller: EntityId,
    /// Called party.
    pub callee: EntityId,
    /// Requested surface.
    pub surface: Surface,
    /// Terms as narrowed by policy.
    pub terms: Terms,
    /// Lifetime policy will permit, seconds.
    pub ttl_secs: u64,
    /// Why the requester wants it.
    pub justification: String,
    /// Who asked.
    pub requester: HumanRef,
    /// Mediators the contract must be addressed to.
    pub mediators: Vec<String>,
    /// Role an approver must hold.
    pub approver_role: Option<String>,
    /// Whether two distinct approvers are needed.
    pub dual_control: bool,
    /// Policy version the decision was made under.
    pub policy_version: String,
    /// Why policy routed it here.
    pub policy_reason: String,
    /// The gates that decided it.
    pub policy_trace: String,
    /// Created at.
    pub created_at: u64,
    /// Lapses at.
    pub expires_at: u64,
    /// Current status.
    pub status: RequestStatus,
}

impl PendingRequest {
    /// The digest an approver signs.
    ///
    /// Covers exactly what the approver was shown — the parties, the surface, the
    /// terms and the lifetime. Widening any of them after the signature invalidates
    /// it, which is the point.
    #[must_use]
    pub fn digest(&self) -> String {
        let mut items = self.surface.items();
        items.sort_unstable();
        let canonical = canonical_json(&serde_json::json!({
            "id": self.id,
            "caller": self.caller.as_str(),
            "callee": self.callee.as_str(),
            "items": items,
            "resources": self.surface.resources,
            "terms": self.terms,
            "ttl_secs": self.ttl_secs,
            "mediators": self.mediators,
        }));
        format!("sha256:{}", sha256_hex(&canonical))
    }

    /// Whether the request has lapsed as of `now`.
    #[must_use]
    pub fn has_lapsed(&self, now: u64) -> bool {
        now >= self.expires_at
    }
}

// ---------------------------------------------------------------------------
// Signed approvals
// ---------------------------------------------------------------------------

/// The claims in an approval JWS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalClaims {
    /// The request being approved.
    pub req: String,
    /// The digest of that request, as the approver saw it.
    pub digest: String,
    /// Policy version in force when the approver signed.
    pub policy_version: String,
    /// Change ticket, where the process demands one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ticket: Option<String>,
    /// When it was signed.
    pub iat: u64,
}

/// An approver's signature over a request.
#[derive(Debug, Clone)]
pub struct ApprovalProof {
    /// Who signed.
    pub by: HumanRef,
    /// The compact JWS.
    pub jws: String,
}

/// Who may approve, and with which keys.
///
/// Roles live beside the keys deliberately: an approver's authority and their
/// ability to prove identity come from the same administered source, so a role
/// cannot be asserted by whoever happens to hold a key.
#[derive(Debug, Default)]
pub struct ApproverRegistry {
    keys: IssuerKeys,
    roles: std::collections::BTreeMap<String, Vec<String>>,
}

impl ApproverRegistry {
    /// An empty registry. No approver can act.
    #[must_use]
    pub fn new() -> ApproverRegistry {
        ApproverRegistry::default()
    }

    /// Register an approver's EC public key and roles.
    pub fn add_ec(
        &mut self,
        id: &HumanRef,
        pem: &[u8],
        alg: contract::Algorithm,
        roles: &[&str],
    ) -> Result<()> {
        self.keys.add_ec_pem(id.as_str(), pem, alg)?;
        self.roles.insert(
            id.as_str().to_string(),
            roles.iter().map(|r| (*r).to_string()).collect(),
        );
        Ok(())
    }

    /// Whether an approver holds a role.
    #[must_use]
    pub fn holds_role(&self, id: &HumanRef, role: &str) -> bool {
        self.roles
            .get(id.as_str())
            .is_some_and(|roles| roles.iter().any(|r| r == role))
    }

    /// Roles an approver holds.
    #[must_use]
    pub fn roles(&self, id: &HumanRef) -> Vec<String> {
        self.roles.get(id.as_str()).cloned().unwrap_or_default()
    }

    /// Whether anyone is registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

/// Sign an approval for a request.
///
/// In production this happens in the approver's own client, with their own key —
/// the control plane only ever verifies. It lives here so the CLI and the tests can
/// exercise the real path rather than a mock.
pub fn sign_approval(
    request: &PendingRequest,
    signer: &IssuerKey,
    ticket: Option<&str>,
    now: u64,
) -> Result<String> {
    let claims = ApprovalClaims {
        req: request.id.clone(),
        digest: request.digest(),
        policy_version: request.policy_version.clone(),
        ticket: ticket.map(str::to_string),
        iat: now,
    };
    contract::sign_detached(&claims, signer)
}

/// Verify an approval against the request it claims to approve.
pub fn verify_approval(
    proof: &ApprovalProof,
    request: &PendingRequest,
    approvers: &ApproverRegistry,
    live_policy_version: &str,
) -> Result<ApprovalClaims> {
    let claims: ApprovalClaims =
        contract::verify_detached(&proof.jws, proof.by.as_str(), &approvers.keys).map_err(|e| {
            WcError::with_detail(
                Code::APPROVAL_SIGNATURE_INVALID,
                format!("{}: {}", proof.by, e.detail()),
            )
        })?;

    if claims.req != request.id {
        return Err(WcError::with_detail(
            Code::APPROVAL_SIGNATURE_INVALID,
            format!("approval names request {}, not {}", claims.req, request.id),
        ));
    }
    // The property that makes an approval more than a row: the approver signed a
    // digest of what they were shown, so a widened surface no longer matches.
    if claims.digest != request.digest() {
        return Err(WcError::with_detail(
            Code::APPROVAL_SIGNATURE_INVALID,
            "the request has changed since it was approved".to_string(),
        ));
    }
    if claims.policy_version != live_policy_version {
        return Err(WcError::with_detail(
            Code::APPROVAL_STALE,
            format!(
                "approved under {}, live policy is {live_policy_version}",
                claims.policy_version
            ),
        ));
    }
    Ok(claims)
}

// ---------------------------------------------------------------------------
// Inputs and outcomes
// ---------------------------------------------------------------------------

/// A request for a connection.
#[derive(Debug, Clone)]
pub struct RequestInput {
    /// Calling party.
    pub caller: EntityId,
    /// Called party.
    pub callee: EntityId,
    /// Requested surface.
    pub surface: Surface,
    /// Requested terms, including declared data classes and jurisdictions.
    pub terms: Terms,
    /// Requested lifetime, seconds.
    pub ttl_secs: u64,
    /// Why.
    pub justification: String,
    /// Who asked.
    pub requester: HumanRef,
    /// Mediators the contract must be addressed to. One artifact per mediator.
    pub mediators: Vec<String>,
}

/// A break-glass request.
#[derive(Debug, Clone)]
pub struct BreakGlassInput {
    /// Calling party.
    pub caller: EntityId,
    /// Called party.
    pub callee: EntityId,
    /// Requested surface. Still bounded by what the callee declared.
    pub surface: Surface,
    /// Terms. Not widened by the emergency.
    pub terms: Terms,
    /// Lifetime in seconds, bounded by [`BreakGlassLimits::max_ttl_secs`].
    pub ttl_secs: u64,
    /// The incident this is for. Mandatory.
    pub incident: String,
    /// Why, in enough words for a reviewer.
    pub justification: String,
    /// Who is asking.
    pub requester: HumanRef,
    /// Mediators the contract must be addressed to.
    pub mediators: Vec<String>,
}

/// Bounds on the emergency path.
///
/// These are what stop break-glass from becoming the normal path. Every one of
/// them is a refusal an operator will meet during an incident, which is
/// uncomfortable and correct: the alternative is an unbounded bypass that nobody
/// notices has become routine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BreakGlassLimits {
    /// Hardest permitted lifetime. One hour by default — long enough to work
    /// through an incident, short enough that nobody plans around it.
    #[serde(default = "default_bg_ttl")]
    pub max_ttl_secs: u64,
    /// How many may be issued per window.
    #[serde(default = "default_bg_per_window")]
    pub max_per_window: u32,
    /// The window, in seconds.
    #[serde(default = "default_bg_window")]
    pub window_secs: u64,
}

fn default_bg_ttl() -> u64 {
    3_600
}
fn default_bg_per_window() -> u32 {
    3
}
fn default_bg_window() -> u64 {
    86_400
}

impl Default for BreakGlassLimits {
    fn default() -> Self {
        BreakGlassLimits {
            max_ttl_secs: default_bg_ttl(),
            max_per_window: default_bg_per_window(),
            window_secs: default_bg_window(),
        }
    }
}

impl BreakGlassLimits {
    /// Validate, refusing the shapes that quietly remove the bound.
    pub fn validate(&self) -> Result<()> {
        if self.max_ttl_secs == 0 {
            return Err(WcError::with_detail(
                Code::CONFIG_INVALID,
                "breakglass.max_ttl_secs = 0 would refuse every emergency contract",
            ));
        }
        if self.max_ttl_secs > 86_400 {
            // A break-glass contract that can outlive the incident is a permanent
            // grant with an exciting name.
            return Err(WcError::with_detail(
                Code::CONFIG_INVALID,
                format!(
                    "breakglass.max_ttl_secs = {} exceeds 24h; that is a standing grant, not an emergency",
                    self.max_ttl_secs
                ),
            ));
        }
        if self.max_per_window == 0 {
            return Err(WcError::with_detail(
                Code::CONFIG_INVALID,
                "breakglass.max_per_window = 0 would refuse every emergency contract",
            ));
        }
        if self.window_secs == 0 {
            return Err(WcError::with_detail(
                Code::CONFIG_INVALID,
                "breakglass.window_secs = 0 would make the budget unbounded",
            ));
        }
        Ok(())
    }
}

/// A deterministic id for a break-glass request, so the digest two approvers sign
/// is the same digest on both terminals.
#[must_use]
fn breakglass_id(input: &BreakGlassInput, now: u64) -> String {
    let mut items = input.surface.items();
    items.sort();
    let seed = format!(
        "bg|{}|{}|{}|{}|{}|{}",
        input.caller,
        input.callee,
        items.join(","),
        input.ttl_secs,
        input.incident,
        now
    );
    format!("bg_{}", &wc_core::util::sha256_hex(&seed)[..12])
}

/// A minted contract and its artifacts.
#[derive(Debug, Clone)]
pub struct Issued {
    /// The registry record.
    pub record: ContractRecord,
    /// One `(audience, jws)` per mediator on the path.
    pub artifacts: Vec<(String, String)>,
    /// Chain sequence of the mint event.
    pub evidence_seq: u64,
}

/// What happened to a request.
#[derive(Debug, Clone)]
pub enum Outcome {
    /// Standing policy issued it with no human in the loop.
    Issued(Issued),
    /// A human must sign for it.
    AwaitingApproval(PendingRequest),
    /// Policy refused it.
    Denied {
        /// Why.
        reason: String,
        /// The gates that decided.
        trace: String,
    },
}

// ---------------------------------------------------------------------------
// The issuer
// ---------------------------------------------------------------------------

/// Issues contracts under a policy, recording every step.
pub struct Issuer<'a> {
    store: &'a mut Store,
    evidence: &'a mut Evidence,
    policy: &'a ConnectPolicy,
    signer: &'a IssuerKey,
    /// Issuer URL recorded in every artifact.
    pub iss: String,
    /// Wall clock.
    pub now: u64,
    /// Who is operating the control plane.
    pub actor: Actor,
    /// How long a pending request waits.
    pub request_ttl_secs: u64,
    /// Enforce or observe.
    ///
    /// A deployment property, not a constant. In observe mode an unattested party
    /// can still be issued a contract — carrying `posture: unattested`, which the
    /// mediator then refuses in enforce mode and records as a finding in observe.
    /// Hardcoding enforce here would make the whole issuance path unusable until
    /// real attestation verifiers exist, which is not a decision this module gets
    /// to make on an operator's behalf.
    pub mode: Mode,
}

impl std::fmt::Debug for Issuer<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Issuer")
            .field("iss", &self.iss)
            .field("now", &self.now)
            .finish_non_exhaustive()
    }
}

impl<'a> Issuer<'a> {
    /// Build an issuer.
    pub fn new(
        store: &'a mut Store,
        evidence: &'a mut Evidence,
        policy: &'a ConnectPolicy,
        signer: &'a IssuerKey,
        iss: &str,
        now: u64,
        actor: Actor,
    ) -> Issuer<'a> {
        Issuer {
            store,
            evidence,
            policy,
            signer,
            iss: iss.to_string(),
            now,
            actor,
            request_ttl_secs: DEFAULT_REQUEST_TTL_SECS,
            mode: Mode::Enforce,
        }
    }

    /// Switch to observe mode.
    #[must_use]
    pub fn observing(mut self) -> Issuer<'a> {
        self.mode = Mode::Observe;
        self
    }

    /// Evaluate a request and either mint it or route it to a human.
    pub fn request(&mut self, input: &RequestInput) -> Result<Outcome> {
        if input.mediators.is_empty() {
            return Err(WcError::with_detail(
                Code::MINT_PRECONDITION_FAILED,
                "a contract must name at least one mediator; there is nowhere to enforce it",
            ));
        }

        let caller = self.entity(&input.caller)?;
        let callee = self.entity(&input.callee)?;

        let conn_req = ConnRequest {
            surface: input.surface.clone(),
            terms: input.terms.clone(),
            ttl_secs: input.ttl_secs,
            justification: input.justification.clone(),
            requester: input.requester.clone(),
        };

        let state = self.standing_state();
        let eval = match self
            .policy
            .evaluate(&conn_req, &caller, &callee, &state, self.now)
        {
            Ok(eval) => eval,
            Err(e) => {
                // A structural failure is recorded too: an estate that only records
                // what it granted cannot show what it turned away.
                self.record_denial(input, &e.to_string(), "structural")?;
                return Err(e);
            }
        };

        let pending = self.build_pending(input, &eval);

        self.store.commit(
            Event::ContractRequest {
                request: Box::new(pending.clone()),
                actor: self.actor.clone(),
            },
            self.now,
            Durability::Durable,
        )?;
        self.evidence.record(
            &LifecycleEvent::new(EventKind::Request, actor_id(&self.actor))
                .with_entities([input.caller.as_str(), input.callee.as_str()])
                .with_reason(eval.reason.clone())
                .with_policy_version(self.policy.version.clone())
                .with_detail(serde_json::json!({
                    "request": pending.id,
                    "decision": eval.decision.as_str(),
                    "trace": eval.trace,
                    "items": pending.surface.items(),
                    "ttl_secs": pending.ttl_secs,
                    "justification": pending.justification,
                })),
            self.now,
        )?;

        match eval.decision {
            ConnDecision::Deny => {
                self.record_denial(input, &eval.reason, &eval.trace)?;
                Ok(Outcome::Denied {
                    reason: eval.reason,
                    trace: eval.trace,
                })
            }
            ConnDecision::RequireApproval => Ok(Outcome::AwaitingApproval(pending)),
            ConnDecision::Allow => {
                // Standing policy: no human, but the approval record says so
                // explicitly rather than leaving the field empty.
                let issued = self.mint(&pending, ApprovalRef::standing(), &caller, &callee)?;
                Ok(Outcome::Issued(issued))
            }
        }
    }

    /// Approve a pending request and mint it.
    pub fn approve(
        &mut self,
        request_id: &str,
        proofs: &[ApprovalProof],
        approvers: &ApproverRegistry,
    ) -> Result<Issued> {
        let pending = self.pending(request_id)?;

        if pending.status != RequestStatus::Pending {
            return Err(WcError::with_detail(
                Code::CONTRACT_ALREADY_ENDED,
                format!("request {request_id} is {:?}", pending.status),
            ));
        }
        if pending.has_lapsed(self.now) {
            // Silence terminates. Reviving a lapsed request would make the SLA
            // advisory rather than real.
            self.lapse(&pending)?;
            return Err(WcError::with_detail(
                Code::APPROVAL_STALE,
                format!(
                    "request {request_id} lapsed at {} and must be re-requested",
                    pending.expires_at
                ),
            ));
        }

        // Every proof must verify, name this request, cover the digest the approver
        // saw, and have been given under the live policy version.
        let mut verified: Vec<(HumanRef, ApprovalClaims)> = Vec::new();
        for proof in proofs {
            let claims = verify_approval(proof, &pending, approvers, &self.policy.version)?;
            verified.push((proof.by.clone(), claims));
        }

        if let Some(role) = &pending.approver_role {
            let holder = verified
                .iter()
                .find(|(by, _)| approvers.holds_role(by, role));
            if holder.is_none() {
                return Err(WcError::with_detail(
                    Code::APPROVER_ROLE_MISSING,
                    format!("this request needs an approver holding {role:?}"),
                ));
            }
        }

        let mut distinct: Vec<&HumanRef> = verified.iter().map(|(by, _)| by).collect();
        distinct.sort_unstable_by(|a, b| a.as_str().cmp(b.as_str()));
        distinct.dedup();

        if pending.dual_control && distinct.len() < 2 {
            return Err(WcError::with_detail(
                Code::DUAL_CONTROL_MISSING,
                format!(
                    "this request needs two distinct approvers, got {}",
                    distinct.len()
                ),
            ));
        }
        if distinct.is_empty() {
            return Err(WcError::with_detail(
                Code::APPROVAL_SIGNATURE_INVALID,
                "no approval was supplied",
            ));
        }

        let approval = ApprovalRef {
            by: Some(distinct[0].clone()),
            jti: None,
            ticket: verified.iter().find_map(|(_, c)| c.ticket.clone()),
            mode: ApprovalMode::Human,
            second: distinct.get(1).map(|h| (*h).clone()),
        };

        self.store.commit(
            Event::ContractApprove {
                request: pending.id.clone(),
                approvers: distinct.iter().map(|h| (*h).clone()).collect(),
                policy_version: self.policy.version.clone(),
                actor: self.actor.clone(),
            },
            self.now,
            Durability::Durable,
        )?;
        self.evidence.record(
            &LifecycleEvent::new(EventKind::Approve, actor_id(&self.actor))
                .with_entities([pending.caller.as_str(), pending.callee.as_str()])
                .with_reason(format!("approved by {}", distinct[0]))
                .with_policy_version(self.policy.version.clone())
                .with_detail(serde_json::json!({
                    "request": pending.id,
                    "approvers": distinct.iter().map(|h| h.as_str()).collect::<Vec<_>>(),
                    "digest": pending.digest(),
                    "ticket": approval.ticket,
                })),
            self.now,
        )?;

        let caller = self.entity(&pending.caller)?;
        let callee = self.entity(&pending.callee)?;
        self.mint(&pending, approval, &caller, &callee)
    }

    // -----------------------------------------------------------------------
    // Break-glass
    // -----------------------------------------------------------------------

    /// Issue a time-boxed emergency contract, bypassing policy evaluation
    /// (T6.6).
    ///
    /// Break-glass exists because incidents do not wait for a zone bar to be
    /// re-cut, and an estate with no emergency path grows an unofficial one —
    /// usually a shared credential and a Slack thread. So the design goal is not
    /// to make this hard, it is to make it **bounded, attributable, and impossible
    /// to leave running.**
    ///
    /// What it bypasses:
    ///
    /// * policy evaluation entirely — no zone bar, no standing caps, no approver
    ///   role routing;
    /// * `Posture::Unattested` and `Posture::Degraded`, which is the state a party
    ///   is usually in precisely when you need this;
    /// * `Lifecycle::Suspended`, so an operator's earlier pause can be reached
    ///   past in an emergency.
    ///
    /// What it can never bypass:
    ///
    /// * **`Posture::Quarantined`.** Quarantine is terminal until a full
    ///   re-admission, and a bypass that reaches into a contained party makes
    ///   containment advisory. This is the one refusal that has no override.
    /// * the callee's declared surface — a contract is a ceiling, never a grant,
    ///   and an emergency does not conjure capability the callee never offered;
    /// * dual control, the TTL ceiling, or the per-window budget below.
    ///
    /// Every override actually used is recorded on the evidence record by name, so
    /// the post-incident question "what did we switch off at 03:14" has an answer
    /// that is not a guess.
    ///
    /// Custody caveat worth stating plainly: this enforces two *distinct
    /// registered identities* with valid signatures over the same digest. It
    /// cannot tell whether one person holds both keys. That is a key-custody
    /// control, not a code one.
    pub fn breakglass(
        &mut self,
        input: &BreakGlassInput,
        proofs: &[ApprovalProof],
        approvers: &ApproverRegistry,
        limits: &BreakGlassLimits,
    ) -> Result<Issued> {
        if input.mediators.is_empty() {
            return Err(WcError::with_detail(
                Code::MINT_PRECONDITION_FAILED,
                "a break-glass contract must name at least one mediator; there is nowhere to enforce it",
            ));
        }
        // Maximally logged means the incident reference is mandatory. An emergency
        // contract nobody can tie to an incident is just an unreviewed contract.
        if input.incident.trim().is_empty() {
            return Err(WcError::with_detail(
                Code::BREAKGLASS_OUTSIDE_POLICY,
                "break-glass requires an incident reference",
            ));
        }
        if input.justification.trim().len() < 12 {
            return Err(WcError::with_detail(
                Code::BREAKGLASS_OUTSIDE_POLICY,
                "break-glass requires a justification a reviewer can read",
            ));
        }
        if input.ttl_secs == 0 || input.ttl_secs > limits.max_ttl_secs {
            return Err(WcError::with_detail(
                Code::BREAKGLASS_OUTSIDE_POLICY,
                format!(
                    "break-glass ttl must be 1..={}s, got {}s",
                    limits.max_ttl_secs, input.ttl_secs
                ),
            ));
        }

        // An unbounded emergency path is just a normal path with worse review. The
        // budget is counted from issued contracts rather than from a counter, so it
        // survives a restart and cannot be reset by one.
        let used = self.breakglass_in_window(limits.window_secs);
        if used >= limits.max_per_window {
            return Err(WcError::with_detail(
                Code::BREAKGLASS_OUTSIDE_POLICY,
                format!(
                    "{used} break-glass contract(s) already issued in the last {}s, budget is {}",
                    limits.window_secs, limits.max_per_window
                ),
            ));
        }

        let caller = self.entity(&input.caller)?;
        let callee = self.entity(&input.callee)?;

        // The one refusal with no override.
        for party in [&caller, &callee] {
            if party.posture == Posture::Quarantined {
                return Err(WcError::with_detail(
                    Code::ENTITY_QUARANTINED,
                    format!(
                        "{} is quarantined; break-glass cannot reach a contained party",
                        party.id
                    ),
                ));
            }
        }
        if caller.id == callee.id {
            return Err(WcError::with_detail(
                Code::MINT_PRECONDITION_FAILED,
                "a party cannot break-glass to itself",
            ));
        }

        // The overrides actually exercised, named for the record.
        let mut overrides: Vec<String> = Vec::new();
        for party in [&caller, &callee] {
            if party.lifecycle != Lifecycle::Active {
                overrides.push(format!("{} lifecycle {:?}", party.id, party.lifecycle));
            }
            if !party.posture.may_connect(self.mode) {
                overrides.push(format!("{} posture {:?}", party.id, party.posture));
            }
        }
        overrides.push("policy evaluation skipped".to_string());

        let pending = self.breakglass_pending(input);

        let mut verified: Vec<HumanRef> = Vec::new();
        for proof in proofs {
            verify_approval(proof, &pending, approvers, &self.policy.version)?;
            verified.push(proof.by.clone());
        }
        verified.sort_unstable_by(|a, b| a.as_str().cmp(b.as_str()));
        verified.dedup();
        if verified.len() < 2 {
            return Err(WcError::with_detail(
                Code::DUAL_CONTROL_MISSING,
                format!(
                    "break-glass always needs two distinct approvers, got {}",
                    verified.len()
                ),
            ));
        }

        let approval = ApprovalRef {
            by: Some(verified[0].clone()),
            jti: None,
            ticket: Some(input.incident.clone()),
            mode: ApprovalMode::BreakGlass,
            second: Some(verified[1].clone()),
        };

        self.evidence.record(
            &LifecycleEvent::new(EventKind::BreakGlass, actor_id(&self.actor))
                .with_entities([input.caller.as_str(), input.callee.as_str()])
                .with_reason(format!(
                    "break-glass for {}: {}",
                    input.incident, input.justification
                ))
                .with_policy_version(self.policy.version.clone())
                .with_detail(serde_json::json!({
                    "incident": input.incident,
                    "approvers": verified.iter().map(|h| h.as_str()).collect::<Vec<_>>(),
                    "surface": pending.surface.items(),
                    "ttl_secs": input.ttl_secs,
                    "expires_at": self.now.saturating_add(input.ttl_secs),
                    "digest": pending.digest(),
                    "overrides": overrides,
                    "budget_used_before": used,
                    "budget": limits.max_per_window,
                    "window_secs": limits.window_secs,
                    "renewable": false,
                })),
            self.now,
        )?;

        // `mint` re-asserts the surface subset and every artifact invariant. It is
        // deliberately the same mint every other contract goes through: an
        // emergency path with its own minting code is an emergency path with its
        // own bugs.
        self.mint_unchecked(&pending, approval, &caller, &callee)
    }

    /// The request two approvers sign over for a break-glass issuance.
    ///
    /// It is never committed — there is no queue to wait in — but reusing the
    /// [`PendingRequest`] shape means the digest and the signature checks are the
    /// same code that guards every other contract. Public so both approvers can
    /// compute the identical digest independently, on separate terminals, without
    /// one of them being trusted to hand it to the other.
    #[must_use]
    pub fn breakglass_pending(&self, input: &BreakGlassInput) -> PendingRequest {
        PendingRequest {
            id: breakglass_id(input, self.now),
            caller: input.caller.clone(),
            callee: input.callee.clone(),
            surface: input.surface.clone(),
            terms: input.terms.clone(),
            ttl_secs: input.ttl_secs,
            justification: input.justification.clone(),
            requester: input.requester.clone(),
            mediators: input.mediators.clone(),
            approver_role: None,
            dual_control: true,
            policy_version: self.policy.version.clone(),
            policy_reason: format!("break-glass: {}", input.incident),
            policy_trace: "break-glass — policy not evaluated".to_string(),
            created_at: self.now,
            expires_at: self.now.saturating_add(self.request_ttl_secs),
            status: RequestStatus::Pending,
        }
    }

    /// Break-glass contracts issued inside `window` seconds of now.
    fn breakglass_in_window(&self, window: u64) -> u32 {
        let floor = self.now.saturating_sub(window);
        self.store
            .projection
            .contracts
            .values()
            .filter(|c| c.approval.mode == ApprovalMode::BreakGlass && c.iat >= floor)
            .count()
            .min(u32::MAX as usize) as u32
    }

    /// A pending request by id, for a client that needs to sign over it.
    pub fn pending_request(&self, id: &str) -> Result<PendingRequest> {
        self.pending(id)
    }

    /// Refuse a pending request.
    pub fn deny(&mut self, request_id: &str, reason: &str) -> Result<()> {
        let pending = self.pending(request_id)?;
        if pending.status != RequestStatus::Pending {
            return Err(WcError::with_detail(
                Code::CONTRACT_ALREADY_ENDED,
                format!("request {request_id} is {:?}", pending.status),
            ));
        }

        self.store.commit(
            Event::ContractDeny {
                request: pending.id.clone(),
                reason: reason.to_string(),
                actor: self.actor.clone(),
            },
            self.now,
            Durability::Durable,
        )?;
        self.evidence.record(
            &LifecycleEvent::new(EventKind::ContractDenied, actor_id(&self.actor))
                .with_entities([pending.caller.as_str(), pending.callee.as_str()])
                .with_reason(reason.to_string())
                .with_policy_version(self.policy.version.clone())
                .with_detail(serde_json::json!({"request": pending.id})),
            self.now,
        )?;
        Ok(())
    }

    /// Mark every pending request that has run out of time.
    ///
    /// Returns the ids that lapsed. Nothing is provisioned: silence terminates.
    pub fn expire_lapsed(&mut self) -> Result<Vec<String>> {
        let lapsed: Vec<PendingRequest> = self
            .store
            .projection
            .requests
            .values()
            .filter(|r| r.status == RequestStatus::Pending && r.has_lapsed(self.now))
            .cloned()
            .collect();

        let mut ids = Vec::new();
        for request in lapsed {
            self.lapse(&request)?;
            ids.push(request.id);
        }
        ids.sort_unstable();
        Ok(ids)
    }

    // -----------------------------------------------------------------------
    // Internals
    // -----------------------------------------------------------------------

    fn entity(&self, id: &EntityId) -> Result<Entity> {
        self.store
            .projection
            .entities
            .get(id)
            .cloned()
            .ok_or_else(|| {
                WcError::with_detail(Code::ENTITY_NOT_FOUND, format!("{id} is not registered"))
            })
    }

    fn pending(&self, id: &str) -> Result<PendingRequest> {
        self.store
            .projection
            .requests
            .get(id)
            .cloned()
            .ok_or_else(|| {
                WcError::with_detail(Code::CONTRACT_NOT_FOUND, format!("no request {id}"))
            })
    }

    /// Standing-issuance counters as of now.
    fn standing_state(&self) -> StandingState {
        let active: Vec<_> = self
            .store
            .projection
            .contracts
            .values()
            .filter(|c| c.status == ContractStatus::Active)
            .collect();
        let standing = active
            .iter()
            .filter(|c| c.approval.mode == ApprovalMode::StandingPolicy)
            .count();
        let window_start = self.now.saturating_sub(
            crate::cpolicy::parse_duration(&self.policy.standing.window).unwrap_or(86_400),
        );
        let issued_in_window = active
            .iter()
            .filter(|c| c.approval.mode == ApprovalMode::StandingPolicy && c.iat >= window_start)
            .count();

        StandingState {
            active_contracts: active.len(),
            standing_contracts: standing,
            issued_in_window: u32::try_from(issued_in_window).unwrap_or(u32::MAX),
        }
    }

    fn build_pending(&self, input: &RequestInput, eval: &ConnEval) -> PendingRequest {
        PendingRequest {
            id: request_id(input, self.now, self.store.log.last_seq()),
            caller: input.caller.clone(),
            callee: input.callee.clone(),
            surface: input.surface.clone(),
            // The narrowed terms, not the requested ones: what a human approves is
            // what policy already permits, never the ask.
            terms: eval.terms.clone(),
            ttl_secs: eval.ttl_secs,
            justification: input.justification.clone(),
            requester: input.requester.clone(),
            mediators: input.mediators.clone(),
            approver_role: eval.approver_role.clone(),
            dual_control: eval.dual_control,
            policy_version: self.policy.version.clone(),
            policy_reason: eval.reason.clone(),
            policy_trace: eval.trace.clone(),
            created_at: self.now,
            expires_at: self.now.saturating_add(self.request_ttl_secs),
            status: RequestStatus::Pending,
        }
    }

    fn lapse(&mut self, request: &PendingRequest) -> Result<()> {
        self.store.commit(
            Event::ContractLapse {
                request: request.id.clone(),
            },
            self.now,
            Durability::Durable,
        )?;
        Ok(())
    }

    fn record_denial(&mut self, input: &RequestInput, reason: &str, trace: &str) -> Result<()> {
        self.evidence.record(
            &LifecycleEvent::new(EventKind::ContractDenied, actor_id(&self.actor))
                .with_entities([input.caller.as_str(), input.callee.as_str()])
                .with_reason(reason.to_string())
                .with_policy_version(self.policy.version.clone())
                .with_detail(serde_json::json!({"trace": trace})),
            self.now,
        )?;
        Ok(())
    }

    /// Build, sign and record the contract (§8.7.2 steps 3–10).
    fn mint(
        &mut self,
        pending: &PendingRequest,
        approval: ApprovalRef,
        caller: &Entity,
        callee: &Entity,
    ) -> Result<Issued> {
        // Preconditions are re-asserted at mint time, not trusted from the request:
        // a party may have been quarantined or suspended while a human deliberated.
        caller.assert_connectable(self.mode)?;
        callee.assert_connectable(self.mode)?;
        self.mint_unchecked(pending, approval, caller, callee)
    }

    /// Mint without the connectability assertion.
    ///
    /// Only break-glass calls this, and only after refusing a quarantined party
    /// itself. Split out rather than parameterised with a `skip_checks` flag,
    /// because a boolean that disables preconditions is the kind of argument that
    /// eventually gets passed `true` by accident.
    fn mint_unchecked(
        &mut self,
        pending: &PendingRequest,
        approval: ApprovalRef,
        caller: &Entity,
        callee: &Entity,
    ) -> Result<Issued> {
        let items = pending.surface.items();
        let surface_digest = callee.pin.surface_digest(&items)?;

        let cid = Cid::new(mint_cid(pending))?;
        let jti = Jti::new(mint_jti(&cid, self.now, self.store.log.last_seq()))?;
        let exp = self.now.saturating_add(pending.ttl_secs);

        let caller_party = Party {
            id: caller.id.clone(),
            zone: caller.zone.clone(),
            tier: caller.tier,
            card: (!caller.pin.is_empty()).then(|| caller.pin.manifest.clone()),
            manifest: None,
            surface_digest: None,
        };
        let callee_party = Party {
            id: callee.id.clone(),
            zone: callee.zone.clone(),
            tier: callee.tier,
            card: None,
            manifest: Some(callee.pin.manifest.clone()),
            surface_digest: Some(surface_digest.clone()),
        };

        let assurance = Assurance {
            attestation: callee
                .provenance
                .iter()
                .map(|p| format!("{}:{}", p.kind, p.reference))
                .collect(),
            reattest_every: format!("{}s", callee.reattest_every),
            posture: callee.posture,
        };

        // One artifact per mediator. Never a multi-audience contract: that would be
        // replayable across enforcement points (§7.8 A2).
        let mut artifacts: Vec<(String, String)> = Vec::new();
        let mut first_jws = String::new();
        for mediator in &pending.mediators {
            let mut payload = ContractPayload::new(
                cid.clone(),
                jti.clone(),
                &self.iss,
                mediator,
                caller_party.clone(),
                callee_party.clone(),
            );
            payload.iat = self.now;
            payload.nbf = self.now;
            payload.exp = exp;
            payload.surface = pending.surface.clone();
            payload.terms = pending.terms.clone();
            payload.assurance = assurance.clone();
            payload.approval = approval.clone();
            payload.policy_version = pending.policy_version.clone();
            payload.schema = wc_core::contract::PAYLOAD_SCHEMA;

            let jws = contract::mint(&payload, self.signer)?;
            if first_jws.is_empty() {
                first_jws = jws.clone();
            }
            artifacts.push((mediator.clone(), jws));
        }

        let record = ContractRecord {
            cid: cid.clone(),
            jti,
            caller: caller.id.clone(),
            callee: callee.id.clone(),
            caller_zone: caller.zone.clone(),
            callee_zone: callee.zone.clone(),
            callee_tier: callee.tier,
            callee_manifest: callee.pin.manifest.clone(),
            surface_digest,
            surface: pending.surface.clone(),
            terms: pending.terms.clone(),
            aud: pending.mediators.clone(),
            jws_sha256: format!("sha256:{}", sha256_hex(&first_jws)),
            status: ContractStatus::Active,
            approval,
            policy_version: pending.policy_version.clone(),
            iat: self.now,
            exp,
            schema: CONTRACT_SCHEMA,
        };

        // Evidence before the record: in a regulated estate, authority that exists
        // with no durable trace of its creation is exactly the gap an audit finds.
        // A blocking sink failure here means nothing is committed.
        let recorded = self.evidence.record(
            &LifecycleEvent::new(EventKind::Mint, actor_id(&self.actor))
                .with_cid(cid.as_str())
                .with_contract_jti(record.jti.as_str())
                .with_entities([caller.id.as_str(), callee.id.as_str()])
                .with_reason(pending.policy_reason.clone())
                .with_policy_version(pending.policy_version.clone())
                .with_detail(serde_json::json!({
                    "request": pending.id,
                    "items": items,
                    "resources": pending.surface.resources,
                    "aud": pending.mediators,
                    "exp": exp,
                    "approval_mode": format!("{:?}", record.approval.mode),
                    "surface_digest": record.surface_digest,
                    "jws_sha256": record.jws_sha256,
                    // Which key signed this, and where that key lives. `kid` alone
                    // would not answer the question an auditor actually asks after a
                    // migration to an HSM — *was anything signed with an on-disk key
                    // after we moved?* A posture that can only be asserted going
                    // forward is one nobody can check backwards.
                    "signing_kid": self.signer.kid(),
                    "key_custody": self.signer.custody().as_str(),
                })),
            self.now,
        )?;

        self.store.commit(
            Event::ContractMint {
                record: Box::new(record.clone()),
            },
            self.now,
            Durability::Durable,
        )?;
        self.store.commit(
            Event::ContractIssued {
                request: pending.id.clone(),
                cid: cid.clone(),
            },
            self.now,
            Durability::Durable,
        )?;

        // Persist the artifacts, or a mediator could never be handed the signed
        // document it is meant to verify (§8.8.1).
        for (audience, jws) in &artifacts {
            self.store.write_artifact(cid.as_str(), audience, jws)?;
        }

        Ok(Issued {
            record,
            artifacts,
            evidence_seq: recorded.seq,
        })
    }
}

fn actor_id(actor: &Actor) -> String {
    match actor {
        Actor::Human { id } => id.as_str().to_string(),
        Actor::Service { id } => format!("service:{id}"),
        Actor::Assurance => "assurance".to_string(),
    }
}

/// A request id, derived so the same ask does not silently create two requests
/// within the same second.
fn request_id(input: &RequestInput, now: u64, seq: u64) -> String {
    let seed = format!(
        "{}|{}|{}|{now}|{seq}",
        input.caller,
        input.callee,
        input.surface.items().join(",")
    );
    format!("req_{}", &sha256_hex(&seed)[..12])
}

/// The connection id (§8.7.2 step 5): content-addressed over the parties and the
/// contracted surface, so the same relationship resolves to the same `cid`.
fn mint_cid(pending: &PendingRequest) -> String {
    let seed = format!(
        "{}|{}|{}|{}",
        pending.caller,
        pending.callee,
        pending.surface.items().join(","),
        pending.id
    );
    format!("conn_{}", &sha256_hex(&seed)[..8])
}

/// The artifact id.
///
/// Derived rather than random, and that is safe: a `jti` is an identifier, not a
/// secret. Predicting one grants nothing, because revocation requires signing a
/// feed event and the artifact itself is signed. Deriving it keeps mints
/// reproducible in tests, and including the log sequence guarantees uniqueness even
/// for two mints of the same `cid` in the same second.
fn mint_jti(cid: &Cid, now: u64, seq: u64) -> String {
    format!("cx_{}", &sha256_hex(&format!("{cid}|{now}|{seq}"))[..16])
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    use wc_core::contract::{Algorithm, IssuerKeys, VerifyOpts};
    use wc_core::model::{Kind, Lifecycle, Pin, Posture, Tier, ZoneId, PIN_ALG};

    use crate::registry::Registry;
    use crate::store::RepinCause;

    const ISSUER_PRIV: &[u8] = include_bytes!("../../../fixtures/keys/test_issuer_es256_priv.pem");
    const ISSUER_PUB: &[u8] = include_bytes!("../../../fixtures/keys/test_issuer_es256_pub.pem");
    const APPROVER_PRIV: &[u8] = include_bytes!("../../../fixtures/keys/test_anchor_priv.pem");
    const APPROVER_PUB: &[u8] = include_bytes!("../../../fixtures/keys/test_anchor_pub.pem");

    const NOW: u64 = 1_785_312_500;
    const MEDIATOR: &str = "warden:mediator:apac-ops";
    static COUNTER: AtomicU32 = AtomicU32::new(0);

    struct TmpDir(PathBuf);
    impl TmpDir {
        fn new(tag: &str) -> TmpDir {
            let n = COUNTER.fetch_add(1, Ordering::SeqCst);
            let p = std::env::temp_dir().join(format!("wc-iss-{}-{tag}-{n}", std::process::id()));
            std::fs::create_dir_all(&p).unwrap();
            TmpDir(p)
        }
        fn state(&self) -> PathBuf {
            self.0.join("state")
        }
        fn evidence(&self) -> PathBuf {
            self.0.join("evidence")
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
    fn dana() -> HumanRef {
        HumanRef::new("human:dana@org").unwrap()
    }
    fn agent_id() -> EntityId {
        EntityId::new("spiffe://org/ns/agents/sa/recon-bot-7").unwrap()
    }
    fn server_id() -> EntityId {
        EntityId::new("spiffe://org/ns/tools/sa/payments-mcp").unwrap()
    }

    fn signer() -> IssuerKey {
        IssuerKey::ec_pem("wc-test-es256", ISSUER_PRIV, Algorithm::ES256).unwrap()
    }

    fn approver_key(kid: &str) -> IssuerKey {
        IssuerKey::ec_pem(kid, APPROVER_PRIV, Algorithm::ES256).unwrap()
    }

    /// An approver registry where cecil is a security architect and dana is not.
    fn approvers() -> ApproverRegistry {
        let mut r = ApproverRegistry::new();
        r.add_ec(
            &cecil(),
            APPROVER_PUB,
            Algorithm::ES256,
            &["security.architect"],
        )
        .unwrap();
        r.add_ec(
            &dana(),
            APPROVER_PUB,
            Algorithm::ES256,
            &["platform.operator"],
        )
        .unwrap();
        r
    }

    fn pin(items: &[&str]) -> Pin {
        Pin {
            alg: PIN_ALG.to_string(),
            manifest: "sha256:m1".to_string(),
            items: items
                .iter()
                .map(|n| ((*n).to_string(), format!("sha256:{n}")))
                .collect::<BTreeMap<_, _>>(),
            pinned_at: NOW - 1_000,
        }
    }

    /// A store with an active agent and an active server at `tier`.
    fn seeded(tmp: &TmpDir, tier: Tier) -> Store {
        let (mut store, _) = Store::open(tmp.state()).unwrap();
        let actor = Actor::Human { id: priya() };

        for (id, kind, zone, entity_tier) in [
            (agent_id(), Kind::Agent, "internal.apac-ops", Tier::TWO),
            (server_id(), Kind::McpServer, "internal.payments", tier),
        ] {
            let mut e = Entity::pending(
                id.clone(),
                kind,
                priya(),
                ZoneId::new(zone).unwrap(),
                entity_tier,
                NOW - 2_000,
            );
            e.service = Some("payments-recon".to_string());
            {
                let mut reg: Registry<'_> = store.registry(actor.clone(), NOW - 2_000);
                reg.put(e).unwrap();
                reg.transition(&id, Lifecycle::Active, "admitted").unwrap();
                reg.set_posture(&id, Posture::Attested, 95).unwrap();
            }
        }
        store
            .registry(actor, NOW - 1_500)
            .repin(
                &server_id(),
                pin(&["get_balance", "list_transactions", "wire_funds"]),
                RepinCause::Admission,
            )
            .unwrap();
        store.log.sync().unwrap();
        store
    }

    /// A reviewed policy: the low-risk case is standing, tier ≤ 2 needs an architect.
    fn policy() -> ConnectPolicy {
        ConnectPolicy::parse(&format!(
            r#"
default = "require_approval"
version = "connect-policy@v9"

[[zone]]
id = "internal.apac-ops"
trust = "internal"
[[zone]]
id = "internal.payments"
trust = "internal"

[standing]
reviewed_at = {}
review_every = "90d"

[[rules]]
caller_zone = "internal.*"
callee_zone = "internal.*"
callee_tier = {{ op = "gt", value = 2 }}
surface = {{ write = false }}
decision = "allow"
ttl_max = "30d"

[[rules]]
callee_tier = {{ op = "lt", value = 3 }}
decision = "require_approval"
approver_role = "security.architect"
reason = "a sensitive callee needs a security architect"
"#,
            NOW - 86_400
        ))
        .unwrap()
    }

    fn input(tools: &[&str]) -> RequestInput {
        RequestInput {
            caller: agent_id(),
            callee: server_id(),
            surface: Surface {
                tools: tools.iter().map(|t| (*t).to_string()).collect(),
                skills: Vec::new(),
                resources: Vec::new(),
            },
            terms: Terms {
                data_classes: vec!["internal".to_string()],
                jurisdictions: vec!["SG".to_string()],
                ..Default::default()
            },
            ttl_secs: 30 * 86_400,
            justification: "APAC daily reconciliation".to_string(),
            requester: priya(),
            mediators: vec![MEDIATOR.to_string()],
        }
    }

    /// Run a closure with an issuer wired to a fresh store and chain.
    fn with_issuer<T>(
        tmp: &TmpDir,
        tier: Tier,
        pol: &ConnectPolicy,
        now: u64,
        f: impl FnOnce(&mut Issuer<'_>) -> T,
    ) -> T {
        let mut store = seeded(tmp, tier);
        let mut evidence = Evidence::open(tmp.evidence()).unwrap();
        let key = signer();
        let mut issuer = Issuer::new(
            &mut store,
            &mut evidence,
            pol,
            &key,
            "https://connect.internal/t/apac",
            now,
            Actor::Human { id: priya() },
        );
        f(&mut issuer)
    }

    // --- break-glass -------------------------------------------------------

    fn bg(tools: &[&str], ttl: u64) -> BreakGlassInput {
        BreakGlassInput {
            caller: agent_id(),
            callee: server_id(),
            surface: Surface {
                tools: tools.iter().map(|t| (*t).to_string()).collect(),
                skills: Vec::new(),
                resources: Vec::new(),
            },
            terms: Terms::default(),
            ttl_secs: ttl,
            incident: "SOC-4471".to_string(),
            justification: "settlement halted, need balance reads to triage".to_string(),
            requester: priya(),
            mediators: vec![MEDIATOR.to_string()],
        }
    }

    /// Two distinct approvers, both signing the digest break-glass will compute.
    fn bg_proofs_from(pending: &PendingRequest, who: &[HumanRef], now: u64) -> Vec<ApprovalProof> {
        who.iter()
            .map(|h| ApprovalProof {
                by: h.clone(),
                jws: sign_approval(pending, &approver_key(h.as_str()), None, now).unwrap(),
            })
            .collect()
    }

    #[test]
    fn break_glass_mints_a_short_dual_controlled_contract() {
        let tmp = TmpDir::new("bg-ok");
        let pol = policy();
        let input = bg(&["get_balance"], 900);
        let issued = with_issuer(&tmp, Tier::ONE, &pol, NOW, |issuer| {
            let proofs = bg_proofs_from(&issuer.breakglass_pending(&input), &[cecil(), dana()], NOW);
            issuer
                .breakglass(&input, &proofs, &approvers(), &BreakGlassLimits::default())
                .expect("break-glass issues")
        });

        assert_eq!(issued.record.approval.mode, ApprovalMode::BreakGlass);
        assert_eq!(issued.record.approval.ticket.as_deref(), Some("SOC-4471"));
        assert!(issued.record.approval.second.is_some(), "dual control recorded");
        assert_eq!(issued.record.exp - issued.record.iat, 900);
        assert_eq!(issued.artifacts.len(), 1);
    }

    #[test]
    fn break_glass_needs_two_distinct_approvers() {
        // One approver signing twice is one approver.
        let tmp = TmpDir::new("bg-dual");
        let pol = policy();
        let input = bg(&["get_balance"], 900);
        let err = with_issuer(&tmp, Tier::THREE, &pol, NOW, |issuer| {
            let proofs = bg_proofs_from(&issuer.breakglass_pending(&input), &[cecil(), cecil()], NOW);
            issuer
                .breakglass(&input, &proofs, &approvers(), &BreakGlassLimits::default())
                .unwrap_err()
        });
        assert_eq!(err.code(), Code::DUAL_CONTROL_MISSING);
    }

    #[test]
    fn break_glass_can_never_reach_a_quarantined_party() {
        // The one refusal with no override. A bypass that reaches into a contained
        // party makes containment advisory.
        let tmp = TmpDir::new("bg-quarantined");
        let pol = policy();
        let input = bg(&["get_balance"], 900);

        let mut store = seeded(&tmp, Tier::THREE);
        store
            .registry(Actor::Human { id: priya() }, NOW - 100)
            .quarantine(&server_id(), "SOC-1", &[])
            .unwrap();
        let mut evidence = Evidence::open(tmp.evidence()).unwrap();
        let key = signer();
        let mut issuer = Issuer::new(
            &mut store,
            &mut evidence,
            &pol,
            &key,
            "https://connect.internal/t/apac",
            NOW,
            Actor::Human { id: priya() },
        );
        let proofs = bg_proofs_from(&issuer.breakglass_pending(&input), &[cecil(), dana()], NOW);
        let err = issuer
            .breakglass(&input, &proofs, &approvers(), &BreakGlassLimits::default())
            .unwrap_err();
        assert_eq!(err.code(), Code::ENTITY_QUARANTINED);
        assert!(err.to_string().contains("cannot reach a contained party"));
    }

    #[test]
    fn break_glass_still_cannot_exceed_the_declared_surface() {
        // A contract is a ceiling, never a grant. An emergency does not conjure
        // capability the callee never offered.
        let tmp = TmpDir::new("bg-surface");
        let pol = policy();
        let input = bg(&["get_balance", "not_a_real_tool"], 900);
        let err = with_issuer(&tmp, Tier::THREE, &pol, NOW, |issuer| {
            let proofs = bg_proofs_from(&issuer.breakglass_pending(&input), &[cecil(), dana()], NOW);
            issuer
                .breakglass(&input, &proofs, &approvers(), &BreakGlassLimits::default())
                .unwrap_err()
        });
        assert_ne!(err.code(), Code::BREAKGLASS_OUTSIDE_POLICY, "not a policy refusal");
        assert!(
            err.to_string().contains("not_a_real_tool")
                || err.to_string().contains("surface"),
            "{err}"
        );
    }

    #[test]
    fn break_glass_overrides_posture_and_a_suspended_lifecycle() {
        // This is the state a party is usually in exactly when break-glass is
        // needed, so refusing here would make the feature useless.
        let tmp = TmpDir::new("bg-override");
        let pol = policy();
        let input = bg(&["get_balance"], 600);

        let mut store = seeded(&tmp, Tier::THREE);
        {
            let mut reg = store.registry(Actor::Human { id: priya() }, NOW - 100);
            reg.set_posture(&server_id(), Posture::Unattested, 20).unwrap();
            reg.transition(&server_id(), Lifecycle::Suspended, "drift").unwrap();
        }
        let mut evidence = Evidence::open(tmp.evidence()).unwrap();
        let key = signer();
        let issued = {
            let mut issuer = Issuer::new(
                &mut store,
                &mut evidence,
                &pol,
                &key,
                "https://connect.internal/t/apac",
                NOW,
                Actor::Human { id: priya() },
            );
            let proofs = bg_proofs_from(&issuer.breakglass_pending(&input), &[cecil(), dana()], NOW);
            issuer
                .breakglass(&input, &proofs, &approvers(), &BreakGlassLimits::default())
                .expect("break-glass overrides posture and suspension")
        };
        assert_eq!(issued.record.approval.mode, ApprovalMode::BreakGlass);

        // And it says which overrides it used, by name.
        let chain = std::fs::read_to_string(tmp.evidence().join("chain.jsonl")).unwrap();
        assert!(chain.contains("contract.breakglass"));
        assert!(chain.contains("policy evaluation skipped"), "{chain}");
        assert!(chain.contains("Unattested"));
        assert!(chain.contains("Suspended"));
    }

    #[test]
    fn break_glass_refuses_the_shapes_that_would_make_it_the_normal_path() {
        let pol = policy();
        let limits = BreakGlassLimits::default();

        for (i, (label, mut input)) in [
            ("no incident", bg(&["get_balance"], 900)),
            ("thin justification", bg(&["get_balance"], 900)),
            ("ttl over the ceiling", bg(&["get_balance"], 7_200)),
            ("zero ttl", bg(&["get_balance"], 0)),
        ]
        .into_iter()
        .enumerate()
        {
            // A fresh root per case: `seeded` registers entities, and re-registering
            // into a live store is drift, not a fixture.
            let tmp = TmpDir::new(&format!("bg-bounds-{i}"));
            match label {
                "no incident" => input.incident = "  ".to_string(),
                "thin justification" => input.justification = "urgent".to_string(),
                _ => {}
            }
            let err = with_issuer(&tmp, Tier::THREE, &pol, NOW, |issuer| {
                let proofs = bg_proofs_from(&issuer.breakglass_pending(&input), &[cecil(), dana()], NOW);
                issuer
                    .breakglass(&input, &proofs, &approvers(), &limits)
                    .unwrap_err()
            });
            assert_eq!(
                err.code(),
                Code::BREAKGLASS_OUTSIDE_POLICY,
                "{label} should be refused as outside policy"
            );
        }
    }

    #[test]
    fn the_break_glass_budget_is_counted_from_issued_contracts() {
        // Counted from the contracts themselves rather than a counter, so it
        // survives a restart and cannot be reset by one.
        let tmp = TmpDir::new("bg-budget");
        let pol = policy();
        let limits = BreakGlassLimits {
            max_per_window: 2,
            ..BreakGlassLimits::default()
        };

        let mut store = seeded(&tmp, Tier::THREE);
        let mut evidence = Evidence::open(tmp.evidence()).unwrap();
        let key = signer();
        let mut issuer = Issuer::new(
            &mut store,
            &mut evidence,
            &pol,
            &key,
            "https://connect.internal/t/apac",
            NOW,
            Actor::Human { id: priya() },
        );

        for i in 0..2u64 {
            // Distinct incidents so the ids differ.
            let mut input = bg(&["get_balance"], 600);
            input.incident = format!("SOC-{i}");
            let proofs = bg_proofs_from(&issuer.breakglass_pending(&input), &[cecil(), dana()], NOW);
            issuer
                .breakglass(&input, &proofs, &approvers(), &limits)
                .unwrap_or_else(|e| panic!("issue {i} failed: {e}"));
        }

        let mut third = bg(&["get_balance"], 600);
        third.incident = "SOC-9".to_string();
        let proofs = bg_proofs_from(&issuer.breakglass_pending(&third), &[cecil(), dana()], NOW);
        let err = issuer
            .breakglass(&third, &proofs, &approvers(), &limits)
            .unwrap_err();
        assert_eq!(err.code(), Code::BREAKGLASS_OUTSIDE_POLICY);
        assert!(err.to_string().contains("budget is 2"), "{err}");
    }

    #[test]
    fn break_glass_limits_reject_a_configuration_that_removes_the_bound() {
        for bad in [
            BreakGlassLimits {
                max_ttl_secs: 0,
                ..Default::default()
            },
            BreakGlassLimits {
                // A break-glass contract that can outlive the incident is a
                // permanent grant with an exciting name.
                max_ttl_secs: 30 * 86_400,
                ..Default::default()
            },
            BreakGlassLimits {
                max_per_window: 0,
                ..Default::default()
            },
            BreakGlassLimits {
                window_secs: 0,
                ..Default::default()
            },
        ] {
            assert_eq!(bad.validate().unwrap_err().code(), Code::CONFIG_INVALID);
        }
        assert!(BreakGlassLimits::default().validate().is_ok());
    }

    #[test]
    fn a_break_glass_approval_is_not_renewable() {
        assert!(!ApprovalRef {
            by: Some(cecil()),
            jti: None,
            ticket: Some("SOC-1".to_string()),
            mode: ApprovalMode::BreakGlass,
            second: Some(dana()),
        }
        .is_renewable());
        assert!(ApprovalRef::standing().is_renewable());
    }

    // --- the standing path ---

    #[test]
    fn standing_policy_mints_without_a_human() {
        let tmp = TmpDir::new("standing");
        let pol = policy();
        let issued = with_issuer(&tmp, Tier::THREE, &pol, NOW, |issuer| {
            match issuer.request(&input(&["get_balance", "list_transactions"])) {
                Ok(Outcome::Issued(issued)) => issued,
                other => panic!("expected an issue, got {other:?}"),
            }
        });

        assert_eq!(issued.record.approval.mode, ApprovalMode::StandingPolicy);
        assert!(issued.record.approval.by.is_none());
        assert_eq!(issued.artifacts.len(), 1);
        assert_eq!(issued.artifacts[0].0, MEDIATOR);
        assert_eq!(issued.record.exp, NOW + 30 * 86_400);
        assert!(issued.evidence_seq > 0);
    }

    #[test]
    fn the_minted_artifact_verifies() {
        // The whole point: what issuance produces must satisfy the verifier the
        // conformance vectors define.
        let tmp = TmpDir::new("verifies");
        let pol = policy();
        let issued = with_issuer(&tmp, Tier::THREE, &pol, NOW, |issuer| {
            match issuer.request(&input(&["get_balance"])) {
                Ok(Outcome::Issued(i)) => i,
                other => panic!("{other:?}"),
            }
        });

        let mut keys = IssuerKeys::new();
        keys.add_ec_pem("wc-test-es256", ISSUER_PUB, Algorithm::ES256)
            .unwrap();
        let verified = contract::verify_artifact(
            &issued.artifacts[0].1,
            &VerifyOpts::new(&keys, MEDIATOR, NOW),
        )
        .expect("a minted contract must verify");

        assert_eq!(verified.payload.cid, issued.record.cid);
        assert_eq!(
            verified.payload.surface.tools,
            vec!["get_balance".to_string()]
        );
        assert_eq!(
            verified.payload.callee.surface_digest.as_deref(),
            Some(issued.record.surface_digest.as_str())
        );
        assert_eq!(verified.payload.policy_version, "connect-policy@v9");
    }

    #[test]
    fn the_digest_matches_the_callee_pin_so_a_mediator_admits() {
        let tmp = TmpDir::new("digest");
        let pol = policy();
        let issued = with_issuer(&tmp, Tier::THREE, &pol, NOW, |issuer| {
            match issuer.request(&input(&["get_balance"])) {
                Ok(Outcome::Issued(i)) => i,
                other => panic!("{other:?}"),
            }
        });
        let expected = pin(&["get_balance", "list_transactions", "wire_funds"])
            .surface_digest(&["get_balance".to_string()])
            .unwrap();
        assert_eq!(issued.record.surface_digest, expected);
    }

    #[test]
    fn one_artifact_per_mediator_never_a_multi_audience_contract() {
        let tmp = TmpDir::new("multi");
        let pol = policy();
        let mut req = input(&["get_balance"]);
        req.mediators = vec![
            "warden:mediator:apac-ops".to_string(),
            "warden:mediator:apac-ops-2".to_string(),
        ];

        let issued = with_issuer(&tmp, Tier::THREE, &pol, NOW, |issuer| {
            match issuer.request(&req) {
                Ok(Outcome::Issued(i)) => i,
                other => panic!("{other:?}"),
            }
        });
        assert_eq!(issued.artifacts.len(), 2);

        // Each artifact names exactly one audience, so replay at the other mediator
        // fails on `aud` (§7.8 A2).
        let mut keys = IssuerKeys::new();
        keys.add_ec_pem("wc-test-es256", ISSUER_PUB, Algorithm::ES256)
            .unwrap();
        let (first_aud, first_jws) = &issued.artifacts[0];
        assert!(
            contract::verify_artifact(first_jws, &VerifyOpts::new(&keys, first_aud, NOW)).is_ok()
        );
        assert_eq!(
            contract::verify_artifact(
                first_jws,
                &VerifyOpts::new(&keys, "warden:mediator:apac-ops-2", NOW)
            )
            .unwrap_err()
            .code(),
            Code::AUDIENCE_MISMATCH
        );
    }

    #[test]
    fn a_contract_with_no_mediator_is_refused() {
        let tmp = TmpDir::new("nomediator");
        let pol = policy();
        let mut req = input(&["get_balance"]);
        req.mediators.clear();
        let err = with_issuer(&tmp, Tier::THREE, &pol, NOW, |issuer| {
            issuer.request(&req).unwrap_err()
        });
        assert_eq!(err.code(), Code::MINT_PRECONDITION_FAILED);
        assert!(err.detail().contains("nowhere to enforce"));
    }

    // --- the approval path ---

    #[test]
    fn a_sensitive_callee_waits_for_a_human_then_mints() {
        let tmp = TmpDir::new("approve");
        let pol = policy();
        let mut store = seeded(&tmp, Tier::ONE);
        let mut evidence = Evidence::open(tmp.evidence()).unwrap();
        let key = signer();
        let registry = approvers();

        let mut issuer = Issuer::new(
            &mut store,
            &mut evidence,
            &pol,
            &key,
            "https://connect.internal",
            NOW,
            Actor::Human { id: priya() },
        );

        let pending = match issuer.request(&input(&["get_balance"])).unwrap() {
            Outcome::AwaitingApproval(p) => p,
            other => panic!("expected to wait for a human, got {other:?}"),
        };
        assert_eq!(pending.approver_role.as_deref(), Some("security.architect"));
        assert_eq!(pending.status, RequestStatus::Pending);
        assert_eq!(pending.expires_at, NOW + DEFAULT_REQUEST_TTL_SECS);

        let proof = ApprovalProof {
            by: cecil(),
            jws: sign_approval(
                &pending,
                &approver_key(cecil().as_str()),
                Some("RISK-4471"),
                NOW,
            )
            .unwrap(),
        };
        let issued = issuer.approve(&pending.id, &[proof], &registry).unwrap();

        assert_eq!(issued.record.approval.mode, ApprovalMode::Human);
        assert_eq!(issued.record.approval.by.as_ref(), Some(&cecil()));
        assert_eq!(issued.record.approval.ticket.as_deref(), Some("RISK-4471"));
        assert_eq!(
            store.projection.requests[&pending.id].status,
            RequestStatus::Minted
        );
    }

    #[test]
    fn an_approver_without_the_role_cannot_sign_for_it() {
        let tmp = TmpDir::new("role");
        let pol = policy();
        let mut store = seeded(&tmp, Tier::ONE);
        let mut evidence = Evidence::open(tmp.evidence()).unwrap();
        let key = signer();
        let registry = approvers();
        let mut issuer = Issuer::new(
            &mut store,
            &mut evidence,
            &pol,
            &key,
            "https://connect.internal",
            NOW,
            Actor::Human { id: priya() },
        );

        let pending = match issuer.request(&input(&["get_balance"])).unwrap() {
            Outcome::AwaitingApproval(p) => p,
            other => panic!("{other:?}"),
        };
        // dana's signature is valid; her role is not.
        let proof = ApprovalProof {
            by: dana(),
            jws: sign_approval(&pending, &approver_key(dana().as_str()), None, NOW).unwrap(),
        };
        let err = issuer
            .approve(&pending.id, &[proof], &registry)
            .unwrap_err();
        assert_eq!(err.code(), Code::APPROVER_ROLE_MISSING);
        assert!(err.detail().contains("security.architect"));
    }

    #[test]
    fn widening_the_request_after_approval_invalidates_the_signature() {
        // The property that makes an approval more than a database row.
        let tmp = TmpDir::new("widen");
        let pol = policy();
        let mut store = seeded(&tmp, Tier::ONE);
        let mut evidence = Evidence::open(tmp.evidence()).unwrap();
        let key = signer();
        let registry = approvers();
        let mut issuer = Issuer::new(
            &mut store,
            &mut evidence,
            &pol,
            &key,
            "https://connect.internal",
            NOW,
            Actor::Human { id: priya() },
        );

        let pending = match issuer.request(&input(&["get_balance"])).unwrap() {
            Outcome::AwaitingApproval(p) => p,
            other => panic!("{other:?}"),
        };
        let proof = ApprovalProof {
            by: cecil(),
            jws: sign_approval(&pending, &approver_key(cecil().as_str()), None, NOW).unwrap(),
        };

        // Someone widens the surface after the human signed.
        let mut widened = pending.clone();
        widened.surface.tools.push("wire_funds".to_string());
        let err = verify_approval(&proof, &widened, &registry, &pol.version).unwrap_err();
        assert_eq!(err.code(), Code::APPROVAL_SIGNATURE_INVALID);
        assert!(err.detail().contains("changed since it was approved"));
    }

    #[test]
    fn an_approval_goes_stale_when_policy_moves() {
        let tmp = TmpDir::new("stale");
        let pol = policy();
        let mut store = seeded(&tmp, Tier::ONE);
        let mut evidence = Evidence::open(tmp.evidence()).unwrap();
        let key = signer();
        let registry = approvers();

        let pending = {
            let mut issuer = Issuer::new(
                &mut store,
                &mut evidence,
                &pol,
                &key,
                "https://connect.internal",
                NOW,
                Actor::Human { id: priya() },
            );
            match issuer.request(&input(&["get_balance"])).unwrap() {
                Outcome::AwaitingApproval(p) => p,
                other => panic!("{other:?}"),
            }
        };
        let proof = ApprovalProof {
            by: cecil(),
            jws: sign_approval(&pending, &approver_key(cecil().as_str()), None, NOW).unwrap(),
        };

        // Policy is republished under a new version before the mint.
        let mut moved = policy();
        moved.version = "connect-policy@v10".to_string();
        let mut issuer = Issuer::new(
            &mut store,
            &mut evidence,
            &moved,
            &key,
            "https://connect.internal",
            NOW + 60,
            Actor::Human { id: priya() },
        );
        let err = issuer
            .approve(&pending.id, &[proof], &registry)
            .unwrap_err();
        assert_eq!(err.code(), Code::APPROVAL_STALE);
        assert!(err.detail().contains("connect-policy@v9"));
    }

    #[test]
    fn a_forged_approval_is_refused() {
        let tmp = TmpDir::new("forged");
        let pol = policy();
        let mut store = seeded(&tmp, Tier::ONE);
        let mut evidence = Evidence::open(tmp.evidence()).unwrap();
        let key = signer();
        let registry = approvers();
        let mut issuer = Issuer::new(
            &mut store,
            &mut evidence,
            &pol,
            &key,
            "https://connect.internal",
            NOW,
            Actor::Human { id: priya() },
        );
        let pending = match issuer.request(&input(&["get_balance"])).unwrap() {
            Outcome::AwaitingApproval(p) => p,
            other => panic!("{other:?}"),
        };

        // Signed by the issuer key, claiming to be cecil. The registry knows cecil's
        // key, and it is not this one.
        let forged = ApprovalProof {
            by: cecil(),
            jws: sign_approval(&pending, &signer(), None, NOW).unwrap(),
        };
        assert_eq!(
            issuer
                .approve(&pending.id, &[forged], &registry)
                .unwrap_err()
                .code(),
            Code::APPROVAL_SIGNATURE_INVALID
        );

        // And an unregistered approver cannot act at all.
        let stranger = HumanRef::new("human:mallory@org").unwrap();
        let unknown = ApprovalProof {
            by: stranger,
            jws: sign_approval(&pending, &approver_key("human:mallory@org"), None, NOW).unwrap(),
        };
        assert_eq!(
            issuer
                .approve(&pending.id, &[unknown], &registry)
                .unwrap_err()
                .code(),
            Code::APPROVAL_SIGNATURE_INVALID
        );
    }

    #[test]
    fn dual_control_needs_two_distinct_humans() {
        let tmp = TmpDir::new("dual");
        // A public callee forces dual control via the trust-level bar.
        let pol = ConnectPolicy::parse(&format!(
            "default = \"require_approval\"\nversion = \"v1\"\n[standing]\nreviewed_at = {}\nreview_every = \"90d\"\n",
            NOW - 86_400
        ))
        .unwrap();

        let mut store = seeded(&tmp, Tier::THREE);
        // Move the callee to a public zone.
        if let Some(e) = store.projection.entities.get_mut(&server_id()) {
            e.zone = ZoneId::new("public").unwrap();
        }
        let mut evidence = Evidence::open(tmp.evidence()).unwrap();
        let key = signer();
        let mut registry = approvers();
        registry
            .add_ec(
                &priya(),
                APPROVER_PUB,
                Algorithm::ES256,
                &["security.architect"],
            )
            .unwrap();

        let mut issuer = Issuer::new(
            &mut store,
            &mut evidence,
            &pol,
            &key,
            "https://connect.internal",
            NOW,
            Actor::Human { id: priya() },
        );
        let pending = match issuer.request(&input(&["get_balance"])).unwrap() {
            Outcome::AwaitingApproval(p) => p,
            other => panic!("{other:?}"),
        };
        assert!(pending.dual_control, "a public callee needs two approvers");

        let one = ApprovalProof {
            by: cecil(),
            jws: sign_approval(&pending, &approver_key(cecil().as_str()), None, NOW).unwrap(),
        };
        let err = issuer
            .approve(&pending.id, std::slice::from_ref(&one), &registry)
            .unwrap_err();
        assert_eq!(err.code(), Code::DUAL_CONTROL_MISSING);

        // The same human twice is still one human.
        let twice = vec![one.clone(), one.clone()];
        assert_eq!(
            issuer
                .approve(&pending.id, &twice, &registry)
                .unwrap_err()
                .code(),
            Code::DUAL_CONTROL_MISSING
        );

        let two = ApprovalProof {
            by: dana(),
            jws: sign_approval(&pending, &approver_key(dana().as_str()), None, NOW).unwrap(),
        };
        let issued = issuer.approve(&pending.id, &[one, two], &registry).unwrap();
        assert!(issued.record.approval.second.is_some());
        assert!(issued.record.approval.satisfies_dual_control());
    }

    // --- denial and lapse ---

    #[test]
    fn a_denied_request_cannot_be_approved_afterwards() {
        let tmp = TmpDir::new("deny");
        let pol = policy();
        let mut store = seeded(&tmp, Tier::ONE);
        let mut evidence = Evidence::open(tmp.evidence()).unwrap();
        let key = signer();
        let registry = approvers();
        let mut issuer = Issuer::new(
            &mut store,
            &mut evidence,
            &pol,
            &key,
            "https://connect.internal",
            NOW,
            Actor::Human { id: priya() },
        );
        let pending = match issuer.request(&input(&["get_balance"])).unwrap() {
            Outcome::AwaitingApproval(p) => p,
            other => panic!("{other:?}"),
        };

        issuer.deny(&pending.id, "not justified").unwrap();
        assert_eq!(
            store.projection.requests[&pending.id].status,
            RequestStatus::Denied
        );

        let mut issuer = Issuer::new(
            &mut store,
            &mut evidence,
            &pol,
            &key,
            "https://connect.internal",
            NOW + 10,
            Actor::Human { id: priya() },
        );
        let proof = ApprovalProof {
            by: cecil(),
            jws: sign_approval(&pending, &approver_key(cecil().as_str()), None, NOW).unwrap(),
        };
        assert_eq!(
            issuer
                .approve(&pending.id, &[proof], &registry)
                .unwrap_err()
                .code(),
            Code::CONTRACT_ALREADY_ENDED
        );
    }

    #[test]
    fn silence_terminates_a_request_and_it_cannot_be_revived() {
        // UC-04 A3: no answer within the SLA and nothing is provisioned.
        let tmp = TmpDir::new("lapse");
        let pol = policy();
        let mut store = seeded(&tmp, Tier::ONE);
        let mut evidence = Evidence::open(tmp.evidence()).unwrap();
        let key = signer();
        let registry = approvers();

        let pending = {
            let mut issuer = Issuer::new(
                &mut store,
                &mut evidence,
                &pol,
                &key,
                "https://connect.internal",
                NOW,
                Actor::Human { id: priya() },
            );
            match issuer.request(&input(&["get_balance"])).unwrap() {
                Outcome::AwaitingApproval(p) => p,
                other => panic!("{other:?}"),
            }
        };

        let later = NOW + DEFAULT_REQUEST_TTL_SECS + 1;
        let mut issuer = Issuer::new(
            &mut store,
            &mut evidence,
            &pol,
            &key,
            "https://connect.internal",
            later,
            Actor::Human { id: priya() },
        );

        // An approval arriving late does not revive it.
        let proof = ApprovalProof {
            by: cecil(),
            jws: sign_approval(&pending, &approver_key(cecil().as_str()), None, NOW).unwrap(),
        };
        let err = issuer
            .approve(&pending.id, &[proof], &registry)
            .unwrap_err();
        assert_eq!(err.code(), Code::APPROVAL_STALE);
        assert!(err.detail().contains("lapsed"));
        assert_eq!(
            store.projection.requests[&pending.id].status,
            RequestStatus::Lapsed
        );
    }

    #[test]
    fn expire_lapsed_sweeps_the_queue() {
        let tmp = TmpDir::new("sweep");
        let pol = policy();
        let mut store = seeded(&tmp, Tier::ONE);
        let mut evidence = Evidence::open(tmp.evidence()).unwrap();
        let key = signer();

        let ids: Vec<String> = {
            let mut issuer = Issuer::new(
                &mut store,
                &mut evidence,
                &pol,
                &key,
                "https://connect.internal",
                NOW,
                Actor::Human { id: priya() },
            );
            let a = match issuer.request(&input(&["get_balance"])).unwrap() {
                Outcome::AwaitingApproval(p) => p.id,
                other => panic!("{other:?}"),
            };
            let b = match issuer.request(&input(&["list_transactions"])).unwrap() {
                Outcome::AwaitingApproval(p) => p.id,
                other => panic!("{other:?}"),
            };
            vec![a, b]
        };

        let mut issuer = Issuer::new(
            &mut store,
            &mut evidence,
            &pol,
            &key,
            "https://connect.internal",
            NOW + DEFAULT_REQUEST_TTL_SECS + 1,
            Actor::Assurance,
        );
        let lapsed = issuer.expire_lapsed().unwrap();
        assert_eq!(lapsed.len(), 2);
        for id in &ids {
            assert_eq!(store.projection.requests[id].status, RequestStatus::Lapsed);
        }
    }

    // --- preconditions re-checked at mint ---

    #[test]
    fn a_party_quarantined_while_a_human_deliberated_stops_the_mint() {
        let tmp = TmpDir::new("quarantined");
        let pol = policy();
        let mut store = seeded(&tmp, Tier::ONE);
        let mut evidence = Evidence::open(tmp.evidence()).unwrap();
        let key = signer();
        let registry = approvers();

        let pending = {
            let mut issuer = Issuer::new(
                &mut store,
                &mut evidence,
                &pol,
                &key,
                "https://connect.internal",
                NOW,
                Actor::Human { id: priya() },
            );
            match issuer.request(&input(&["get_balance"])).unwrap() {
                Outcome::AwaitingApproval(p) => p,
                other => panic!("{other:?}"),
            }
        };

        // The SOC contains the callee while the architect is still thinking. This
        // callee is tier 1, so containing it is itself dual-controlled.
        store
            .registry(Actor::Human { id: priya() }, NOW + 100)
            .quarantine(&server_id(), "SOC-2291", &[priya(), cecil()])
            .unwrap();

        let proof = ApprovalProof {
            by: cecil(),
            jws: sign_approval(&pending, &approver_key(cecil().as_str()), None, NOW).unwrap(),
        };
        let mut issuer = Issuer::new(
            &mut store,
            &mut evidence,
            &pol,
            &key,
            "https://connect.internal",
            NOW + 200,
            Actor::Human { id: priya() },
        );
        let err = issuer
            .approve(&pending.id, &[proof], &registry)
            .unwrap_err();
        assert_eq!(err.code(), Code::ENTITY_QUARANTINED);
        assert!(!store
            .projection
            .contracts
            .values()
            .any(|c| c.callee == server_id()));
    }

    #[test]
    fn a_surface_the_callee_never_declared_is_refused_before_anything_is_recorded() {
        let tmp = TmpDir::new("subset");
        let pol = policy();
        let err = with_issuer(&tmp, Tier::THREE, &pol, NOW, |issuer| {
            issuer
                .request(&input(&["get_balance", "invent_money"]))
                .unwrap_err()
        });
        assert_eq!(err.code(), Code::SURFACE_NOT_SUBSET);
        assert!(err.detail().contains("invent_money"));
    }

    #[test]
    fn a_policy_denial_is_recorded_as_evidence() {
        // An estate that only records what it granted cannot show what it refused.
        let tmp = TmpDir::new("denyrecord");
        let pol = ConnectPolicy::parse(&format!(
            "default = \"deny\"\nversion = \"v1\"\n[standing]\nreviewed_at = {}\nreview_every = \"90d\"\n",
            NOW - 86_400
        ))
        .unwrap();

        let outcome = with_issuer(&tmp, Tier::THREE, &pol, NOW, |issuer| {
            issuer.request(&input(&["get_balance"])).unwrap()
        });
        assert!(matches!(outcome, Outcome::Denied { .. }));

        let entries = Evidence::entries(tmp.evidence()).unwrap();
        assert!(entries.iter().any(|e| e.kind == "contract.request"));
        assert!(entries.iter().any(|e| e.kind == "contract.deny"));
    }

    // --- durability ---

    #[test]
    fn requests_and_contracts_survive_a_reopen() {
        let tmp = TmpDir::new("durable");
        let pol = policy();
        let (request_id, cid) = {
            let mut store = seeded(&tmp, Tier::THREE);
            let mut evidence = Evidence::open(tmp.evidence()).unwrap();
            let key = signer();
            let mut issuer = Issuer::new(
                &mut store,
                &mut evidence,
                &pol,
                &key,
                "https://connect.internal",
                NOW,
                Actor::Human { id: priya() },
            );
            let issued = match issuer.request(&input(&["get_balance"])).unwrap() {
                Outcome::Issued(i) => i,
                other => panic!("{other:?}"),
            };
            let req = store
                .projection
                .requests
                .keys()
                .next()
                .cloned()
                .expect("a request was recorded");
            (req, issued.record.cid.clone())
        };

        let (store, report) = Store::open(tmp.state()).unwrap();
        assert!(report.is_clean(), "{report:?}");
        assert_eq!(
            store.projection.requests[&request_id].status,
            RequestStatus::Minted
        );
        assert!(store.projection.contracts.contains_key(&cid));
        assert_eq!(store.projection.contracts_for_pin("sha256:m1"), vec![cid]);
    }

    #[test]
    fn a_snapshot_carries_pending_requests() {
        // Compaction must not forget work a human has not answered yet.
        let tmp = TmpDir::new("snapshot");
        let pol = policy();
        let request_id = {
            let mut store = seeded(&tmp, Tier::ONE);
            let mut evidence = Evidence::open(tmp.evidence()).unwrap();
            let key = signer();
            let mut issuer = Issuer::new(
                &mut store,
                &mut evidence,
                &pol,
                &key,
                "https://connect.internal",
                NOW,
                Actor::Human { id: priya() },
            );
            let pending = match issuer.request(&input(&["get_balance"])).unwrap() {
                Outcome::AwaitingApproval(p) => p,
                other => panic!("{other:?}"),
            };
            store.snapshot().unwrap();
            pending.id
        };

        let (store, _) = Store::open(tmp.state()).unwrap();
        assert_eq!(
            store.projection.requests[&request_id].status,
            RequestStatus::Pending
        );
    }

    // --- identifiers ---

    #[test]
    fn the_cid_is_content_addressed_and_the_jti_is_unique() {
        let tmp = TmpDir::new("ids");
        let pol = policy();
        let first = with_issuer(&tmp, Tier::THREE, &pol, NOW, |issuer| {
            match issuer.request(&input(&["get_balance"])).unwrap() {
                Outcome::Issued(i) => i,
                other => panic!("{other:?}"),
            }
        });

        let tmp2 = TmpDir::new("ids2");
        let second = with_issuer(&tmp2, Tier::THREE, &pol, NOW, |issuer| {
            match issuer.request(&input(&["get_balance"])).unwrap() {
                Outcome::Issued(i) => i,
                other => panic!("{other:?}"),
            }
        });

        // The same relationship over the same surface resolves to the same cid.
        assert_eq!(first.record.cid, second.record.cid);
        // A different surface does not.
        let tmp3 = TmpDir::new("ids3");
        let other = with_issuer(&tmp3, Tier::THREE, &pol, NOW, |issuer| {
            match issuer.request(&input(&["list_transactions"])).unwrap() {
                Outcome::Issued(i) => i,
                other => panic!("{other:?}"),
            }
        });
        assert_ne!(first.record.cid, other.record.cid);
        assert!(first.record.cid.as_str().starts_with("conn_"));
        assert!(first.record.jti.as_str().starts_with("cx_"));
    }
}
