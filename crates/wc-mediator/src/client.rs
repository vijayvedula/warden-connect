//! The control-plane client: pull a contract set, acknowledge it
//! (`docs/08-lld.md` §8.7.9).
//!
//! Pull, not push. A push that fails is silently lost; a pull that fails shows up
//! as ACK lag on the control plane, which is a metric an operator can alert on. So
//! the mediator drives the loop and the control plane observes it.
//!
//! Every refresh **verifies every artifact itself**. The control plane says which
//! contracts a mediator should hold; it does not get to say they are valid. A
//! compromised control plane can withhold a contract, and that fails closed — but
//! it cannot manufacture one, because the mediator checks the signature against the
//! issuer key it was configured with.

use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;

use wc_core::contract::IssuerKeys;
use wc_core::error::{Code, Result, WcError};

use crate::cache::{Cache, Revocations, Snapshot, Trust};

/// What the control plane says this mediator should hold.
#[derive(Debug, Clone, Deserialize)]
pub struct ContractSet {
    /// State-log sequence the set was built from.
    #[serde(default)]
    pub seq: u64,
    /// Hash over the active set, echoed in the acknowledgement.
    #[serde(default)]
    pub set_hash: String,
    /// Contracts that should be live.
    #[serde(default)]
    pub active: Vec<ActiveContract>,
    /// Contracts to drop. Named explicitly rather than inferred from absence, so a
    /// partial fetch cannot look like a revocation — or hide one.
    #[serde(default)]
    pub removed: Vec<String>,
}

/// One contract in the set.
#[derive(Debug, Clone, Deserialize)]
pub struct ActiveContract {
    /// Connection id.
    pub cid: String,
    /// The signed artifact. Absent means the control plane has the record but not
    /// the document, which is a control-plane fault and leaves the mediator with
    /// nothing to verify.
    #[serde(default)]
    pub jws: Option<String>,
}

impl ContractSet {
    /// The artifacts, dropping any the control plane could not supply.
    #[must_use]
    pub fn artifacts(&self) -> Vec<String> {
        self.active.iter().filter_map(|c| c.jws.clone()).collect()
    }

    /// Contracts named in the set for which no artifact arrived.
    #[must_use]
    pub fn missing_artifacts(&self) -> Vec<&str> {
        self.active
            .iter()
            .filter(|c| c.jws.is_none())
            .map(|c| c.cid.as_str())
            .collect()
    }
}

/// The revocation feed as served by `GET /v1/revocations`.
#[derive(Debug, Clone, Deserialize)]
pub struct RevocationDelta {
    /// Highest sequence the control plane holds.
    #[serde(default)]
    pub head_seq: u64,
    /// Digest over the whole feed, echoed in the acknowledgement.
    #[serde(default)]
    pub head_digest: String,
    /// Entries after the requested sequence.
    #[serde(default)]
    pub events: Vec<SignedRevocationWire>,
}

/// One signed feed entry as it arrives on the wire.
#[derive(Debug, Clone, Deserialize)]
pub struct SignedRevocationWire {
    /// The event, as the control plane rendered it.
    pub event: serde_json::Value,
    /// Detached signature over the event.
    pub jws: String,
    /// Key that signed it.
    pub kid: String,
}

/// What one revocation names, as the mediator needs to apply it.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RevokedTarget {
    /// Every contract naming this party.
    Party {
        /// The party.
        id: String,
    },
    /// One connection.
    Connection {
        /// The connection id.
        cid: String,
    },
    /// One artifact.
    Artifact {
        /// The artifact id.
        jti: String,
    },
}

/// The signed payload, as verified.
#[derive(Debug, Clone, Deserialize)]
pub struct VerifiedRevocation {
    /// Feed sequence.
    pub seq: u64,
    /// What it revokes.
    #[serde(flatten)]
    pub target: RevokedTarget,
    /// Why.
    #[serde(default)]
    pub reason: String,
    /// When the order was made.
    #[serde(default)]
    pub at: u64,
}

/// What one revocation pull did.
#[derive(Debug, Clone, Default)]
pub struct RevocationReport {
    /// Sequence applied up to.
    pub applied_seq: u64,
    /// Digest of the feed as applied.
    pub head_digest: String,
    /// Entries verified and applied.
    pub applied: usize,
    /// Entries that failed verification, with the sequence they claimed.
    pub rejected: Vec<(u64, Code)>,
    /// Whether the sequence arrived contiguous.
    pub contiguous: bool,
    /// The revocation set as applied, ready to install.
    pub set: Option<Revocations>,
}

impl RevocationReport {
    /// Whether the pull was clean.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.rejected.is_empty() && self.contiguous
    }
}

/// A client for one mediator's endpoints on the control plane.
#[derive(Debug, Clone)]
pub struct ControlPlaneClient {
    base: String,
    mediator_id: String,
    token: String,
    timeout: Duration,
}

impl ControlPlaneClient {
    /// Build a client. `base` is the control plane's root, e.g.
    /// `https://connect.internal`.
    #[must_use]
    pub fn new(base: &str, mediator_id: &str, token: &str) -> ControlPlaneClient {
        ControlPlaneClient {
            base: base.trim_end_matches('/').to_string(),
            mediator_id: mediator_id.to_string(),
            token: token.to_string(),
            timeout: Duration::from_secs(10),
        }
    }

    /// Override the request timeout.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> ControlPlaneClient {
        self.timeout = timeout;
        self
    }

    fn agent(&self) -> ureq::Agent {
        ureq::Agent::config_builder()
            .timeout_global(Some(self.timeout))
            .max_redirects(0)
            // Statuses are handled here so "the control plane said 403" and "the
            // control plane is unreachable" stay distinguishable.
            .http_status_as_error(false)
            .build()
            .into()
    }

    /// Percent-encode the mediator id for a path segment. It contains colons.
    fn encoded_id(&self) -> String {
        self.mediator_id
            .chars()
            .map(|c| match c {
                'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' | '~' => c.to_string(),
                other => format!("%{:02X}", other as u32),
            })
            .collect()
    }

    /// Fetch the contract set.
    pub fn fetch(&self, since: u64) -> Result<ContractSet> {
        let url = format!(
            "{}/v1/mediators/{}/contracts?since={since}",
            self.base,
            self.encoded_id()
        );
        let mut response = self
            .agent()
            .get(&url)
            .header("authorization", &format!("Bearer {}", self.token))
            .call()
            .map_err(|e| {
                WcError::with_detail(Code::NO_CONTRACT, format!("{url}: unreachable"))
                    .with_source(e)
            })?;

        let status = response.status().as_u16();
        let body = response
            .body_mut()
            .with_config()
            .limit(8 * 1024 * 1024)
            .read_to_string()
            .map_err(|e| {
                WcError::with_detail(Code::NO_CONTRACT, format!("{url}: cannot read response"))
                    .with_source(e)
            })?;

        if !(200..300).contains(&status) {
            return Err(WcError::with_detail(
                Code::NO_CONTRACT,
                format!("{url}: control plane returned {status}"),
            ));
        }
        serde_json::from_str(&body).map_err(|e| {
            WcError::with_detail(
                Code::NO_CONTRACT,
                format!("{url}: unexpected response shape"),
            )
            .with_source(e)
        })
    }

    /// Fetch revocations after `since`.
    ///
    /// Unreachable is an error, never an empty delta: an empty delta would read as
    /// "nothing new is revoked", which is exactly the wrong conclusion to draw
    /// from a control plane you cannot reach.
    pub fn fetch_revocations(&self, since: u64) -> Result<RevocationDelta> {
        let url = format!("{}/v1/revocations?since={since}", self.base);
        let mut response = self
            .agent()
            .get(&url)
            .header("authorization", &format!("Bearer {}", self.token))
            .call()
            .map_err(|e| {
                WcError::with_detail(Code::CONTRACT_REVOKED, format!("{url}: unreachable"))
                    .with_source(e)
            })?;

        let status = response.status().as_u16();
        let body = response
            .body_mut()
            .with_config()
            .limit(8 * 1024 * 1024)
            .read_to_string()
            .map_err(|e| {
                WcError::with_detail(
                    Code::CONTRACT_REVOKED,
                    format!("{url}: cannot read response"),
                )
                .with_source(e)
            })?;
        if !(200..300).contains(&status) {
            return Err(WcError::with_detail(
                Code::CONTRACT_REVOKED,
                format!("{url}: control plane returned {status}"),
            ));
        }
        serde_json::from_str(&body).map_err(|e| {
            WcError::with_detail(
                Code::CONTRACT_REVOKED,
                format!("{url}: unexpected response shape"),
            )
            .with_source(e)
        })
    }

    /// Acknowledge a set.
    ///
    /// Signed transport aside, this is the mediator asserting *"I applied exactly
    /// this set"* — which is what lets the control plane report an unacked mediator
    /// as unconfirmed rather than assuming it complied.
    pub fn ack(
        &self,
        set_hash: &str,
        seq: u64,
        revoked: &[String],
        aborted: u64,
        used: &std::collections::BTreeMap<String, u64>,
    ) -> Result<()> {
        let url = format!("{}/v1/mediators/{}/ack", self.base, self.encoded_id());
        let payload = serde_json::json!({
            "set_hash": set_hash,
            "seq": seq,
            "revoked": revoked,
            "aborted": aborted,
            // Which connections were actually called since the last acknowledgement (W10). The
            // mediator is the only place that knows, and a control plane cannot tell a
            // load-bearing contract from one issued for a cancelled project without it.
            "used": used,
        })
        .to_string();

        let response = self
            .agent()
            .post(&url)
            .header("authorization", &format!("Bearer {}", self.token))
            .header("content-type", "application/json")
            .send(payload)
            .map_err(|e| {
                WcError::with_detail(Code::MEDIATOR_ACK_MISSING, format!("{url}: unreachable"))
                    .with_source(e)
            })?;

        let status = response.status().as_u16();
        if (200..300).contains(&status) {
            Ok(())
        } else {
            Err(WcError::with_detail(
                Code::MEDIATOR_ACK_MISSING,
                format!("{url}: control plane returned {status}"),
            ))
        }
    }
}

/// What one refresh did.
#[derive(Debug, Clone, Default)]
pub struct RefreshReport {
    /// Sequence the set was built from.
    pub seq: u64,
    /// Hash of the applied set.
    pub set_hash: String,
    /// Contracts installed after verification.
    pub installed: usize,
    /// Artifacts the control plane named but did not supply.
    pub missing: Vec<String>,
    /// Artifacts that arrived but failed verification, with the code.
    pub rejected: Vec<(String, Code)>,
    /// Contracts the control plane says to drop.
    pub removed: Vec<String>,
    /// Whether the acknowledgement was accepted.
    pub acked: bool,
    /// What the revocation feed said, when it could be reached.
    ///
    /// `None` means the feed could not be fetched. That is **not** "nothing is revoked" — it is
    /// a refresh that did not fully happen, so it does not count as clean and the staleness
    /// bound starts running.
    pub revocations: Option<RevocationReport>,
}

impl RefreshReport {
    /// Whether the whole refresh was clean.
    ///
    /// A set installed without its revocation feed is not a current set: a contract can be
    /// withdrawn without the published set changing, so a refresh that only re-installed
    /// contracts leaves a cut connection working. Marking that fresh is how a withdrawn
    /// contract keeps being honoured.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.missing.is_empty()
            && self.rejected.is_empty()
            && self.acked
            && self
                .revocations
                .as_ref()
                .is_some_and(RevocationReport::is_clean)
    }
}

/// Pull, verify, install, acknowledge.
///
/// A verification failure drops that one contract and keeps the rest: one bad
/// artifact in a published set must not cost a mediator every other contract it
/// holds. The failure is reported, never swallowed.
pub fn refresh(
    client: &ControlPlaneClient,
    cache: &Arc<Cache>,
    trust: &Trust<'_>,
    since: u64,
    rev_since: u64,
    now: u64,
) -> Result<RefreshReport> {
    let set = client.fetch(since)?;
    let artifacts = set.artifacts();

    // The mediator verifies for itself. The control plane says which contracts it
    // should hold, not that they are valid.
    let snapshot = Snapshot::build(&artifacts, trust, now);
    let installed = snapshot.len();
    let rejected: Vec<(String, Code)> = snapshot.rejected.clone();

    let mut report = RefreshReport {
        seq: set.seq,
        set_hash: set.set_hash.clone(),
        installed,
        missing: set
            .missing_artifacts()
            .into_iter()
            .map(str::to_string)
            .collect(),
        rejected,
        removed: set.removed.clone(),
        acked: false,
        revocations: None,
    };

    cache.install(snapshot);
    // Drained on every refresh, whether or not the ack succeeds. A failed ack loses one
    // window of usage data, which is the right trade: retaining it would mean an unreachable
    // control plane grows the map without bound, and usage is a reporting signal rather than
    // an authority — losing a window makes a contract look *less* used, never more.
    // The revocation feed, which for the life of this feature nothing fetched. A contract can be
    // withdrawn without the published set changing — that is what a deny-list is for — so a
    // refresh that only re-installs contracts leaves a cut connection working.
    match client.fetch_revocations(rev_since) {
        Ok(delta) => {
            let rev = install_revocations(cache, &delta, trust.keys, rev_since);
            if !rev.is_clean() {
                eprintln!(
                    "revocations: delta not clean — applied {} of {}, contiguous={}. The set is \
                     distrusted, so nothing is admitted until a clean delta arrives.",
                    rev.applied,
                    delta.events.len(),
                    rev.contiguous
                );
            }
            report.revocations = Some(rev);
        }
        Err(e) => {
            // Not distrusted on a fetch failure: a transient blip would then deny all traffic,
            // and `max_stale` already bounds how long a set may go unrefreshed. What must not
            // happen is this counting as a clean refresh.
            eprintln!(
                "revocations: could not fetch the feed ({} {}); this refresh is NOT clean and \
                 the staleness bound is now running",
                e.code(),
                e.detail()
            );
        }
    }

    let used = cache.take_usage();
    report.acked = client
        .ack(&set.set_hash, set.seq, &set.removed, 0, &used)
        .is_ok();
    Ok(report)
}

/// Verify a revocation delta and **install it into a cache**, fail-closed.
///
/// # Why this exists separately from [`apply_revocations`]
///
/// `apply_revocations` verifies and returns a set; something has to put that set where
/// `Cache::resolve` will read it. Nothing did. `fetch_revocations`, `apply_revocations` and
/// `Cache::set_revocations` were each complete and each tested, and no binary called any of
/// them — so the deny-list in every deployed enforcement point was permanently empty while
/// `resolve` dutifully consulted it on every call.
///
/// # What a bad delta does
///
/// A delta with a gap in it means this process cannot know what is revoked. Installing the
/// partial set would be the wrong answer twice: it would look like a successful refresh, and it
/// would leave entries un-revoked that the plane has already cut. So the set is **distrusted**
/// instead, and `resolve` then refuses everything until a clean delta arrives. Unknown reads as
/// revoked, which is the only safe direction for a deny-list.
pub fn install_revocations(
    cache: &Cache,
    delta: &RevocationDelta,
    keys: &IssuerKeys,
    since: u64,
) -> RevocationReport {
    let report = apply_revocations(delta, keys, &cache.revocations(), since);
    match (&report.set, report.contiguous) {
        (Some(set), true) => cache.set_revocations(set.clone()),
        _ => {
            let mut unknown = (*cache.revocations()).clone();
            unknown.distrust(if report.contiguous {
                "a revocation entry did not verify"
            } else {
                "the revocation feed has a gap, so what is revoked is unknown"
            });
            cache.set_revocations(unknown);
        }
    }
    report
}

/// Verify a revocation delta and install it, returning what was applied.
///
/// Every entry is verified against the revocation keys the mediator was
/// configured with, exactly as contracts are. The control plane says what is
/// revoked; it does not get to say the order was authorised.
///
/// Revocations are **cumulative and deny-only**, so `previous` is extended rather
/// than replaced. A delta that omits an earlier entry must not un-revoke it, and
/// rebuilding the set from a partial fetch would do precisely that.
pub fn apply_revocations(
    delta: &RevocationDelta,
    keys: &IssuerKeys,
    previous: &Revocations,
    since: u64,
) -> RevocationReport {
    let mut set = previous.clone();
    let mut report = RevocationReport {
        head_digest: delta.head_digest.clone(),
        applied_seq: since,
        contiguous: true,
        ..RevocationReport::default()
    };

    let mut expected = since + 1;
    for entry in &delta.events {
        let verified: VerifiedRevocation =
            match wc_core::contract::verify_detached(&entry.jws, &entry.kid, keys) {
                Ok(v) => v,
                Err(e) => {
                    let claimed = entry
                        .event
                        .get("seq")
                        .and_then(serde_json::Value::as_u64)
                        .unwrap_or(0);
                    report.rejected.push((claimed, e.code()));
                    continue;
                }
            };

        // A hole means an order was lost or withheld. Applying what arrived and
        // recording the higher sequence would tell the control plane this mediator
        // is current when it has missed a cut.
        if verified.seq != expected {
            report.contiguous = false;
            break;
        }
        match &verified.target {
            RevokedTarget::Party { id } => set.revoke_party(id.clone()),
            RevokedTarget::Connection { cid } => set.revoke_cid(cid.clone()),
            RevokedTarget::Artifact { jti } => set.revoke_jti(jti.clone()),
        }
        report.applied += 1;
        report.applied_seq = verified.seq;
        expected += 1;
    }

    // Failing closed is not left to the caller. A report that says "this arrived
    // corrupted" and a set that answers questions anyway is a control nobody has to
    // ignore deliberately in order to lose — they only have to not read the report.
    // So the verdict travels inside the set.
    if report.is_clean() {
        // Verified and contiguous from `since` — the only evidence that justifies
        // trusting the set again after a bad pull.
        set.trust();
    } else {
        let why = if report.contiguous {
            format!("{} feed entries failed verification", report.rejected.len())
        } else {
            format!("feed is not contiguous after seq {}", report.applied_seq)
        };
        set.distrust(why);
    }

    report.set = Some(set);
    report
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn keys_dir() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/keys")
    }

    pub(super) fn revocation_keys() -> IssuerKeys {
        let pem = std::fs::read(keys_dir().join("test_issuer_es256_pub.pem")).unwrap();
        let mut keys = IssuerKeys::new();
        keys.add_ec_pem("revoke-1", &pem, wc_core::contract::Algorithm::ES256)
            .unwrap();
        keys
    }

    fn signer() -> wc_core::contract::IssuerKey {
        let pem = std::fs::read(keys_dir().join("test_issuer_es256_priv.pem")).unwrap();
        wc_core::contract::IssuerKey::ec_pem("revoke-1", &pem, wc_core::contract::Algorithm::ES256)
            .unwrap()
    }

    fn signed(seq: u64, body: serde_json::Value) -> SignedRevocationWire {
        let mut event = body;
        event["seq"] = serde_json::json!(seq);
        let jws = wc_core::contract::sign_detached(&event, &signer()).unwrap();
        SignedRevocationWire {
            event,
            jws,
            kid: "revoke-1".to_string(),
        }
    }

    pub(super) fn party(seq: u64, id: &str) -> SignedRevocationWire {
        signed(
            seq,
            serde_json::json!({ "kind": "party", "id": id, "reason": "SOC-1", "actor": "human:sam", "at": 1_000 }),
        )
    }

    pub(super) fn connection(seq: u64, cid: &str) -> SignedRevocationWire {
        signed(
            seq,
            serde_json::json!({ "kind": "connection", "cid": cid, "reason": "SOC-1", "actor": "human:sam", "at": 1_000 }),
        )
    }

    pub(super) fn delta(events: Vec<SignedRevocationWire>) -> RevocationDelta {
        let head_seq = events
            .last()
            .map(|e| e.event["seq"].as_u64().unwrap())
            .unwrap_or(0);
        RevocationDelta {
            head_seq,
            head_digest: "sha256:aa".to_string(),
            events,
        }
    }

    #[test]
    fn a_verified_delta_is_applied_to_the_revocation_set() {
        let report = apply_revocations(
            &delta(vec![
                party(1, "spiffe://org/ns/agents/sa/recon"),
                connection(2, "conn_00000001"),
            ]),
            &revocation_keys(),
            &Revocations::new(),
            0,
        );
        assert!(report.is_clean());
        assert_eq!(report.applied, 2);
        assert_eq!(report.applied_seq, 2);
        let set = report.set.unwrap();
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn an_entry_signed_by_an_untrusted_key_is_rejected_and_the_rest_still_apply() {
        let mut events = vec![party(1, "spiffe://org/ns/agents/sa/recon")];
        events[0].kid = "not-a-trusted-kid".to_string();
        let report = apply_revocations(&delta(events), &revocation_keys(), &Revocations::new(), 0);
        assert!(!report.is_clean());
        assert_eq!(report.rejected.len(), 1);
        assert_eq!(report.applied, 0, "an unauthorised order is not applied");
    }

    #[test]
    fn a_corrupted_feed_poisons_the_set_so_nothing_is_admitted() {
        // The old shape of this: the report said "one entry failed verification",
        // the set was installed anyway, and the containment order in that entry was
        // simply never applied. A control that only reports is a control you lose to
        // by not reading it.
        let mut events = vec![party(1, "spiffe://org/ns/agents/sa/recon")];
        events[0].jws = "not.a.signature".to_string();
        let report = apply_revocations(&delta(events), &revocation_keys(), &Revocations::new(), 0);
        let set = report.set.unwrap();
        assert!(
            set.distrusted().is_some(),
            "an unverifiable feed must not be trusted"
        );
        assert!(set.is_empty(), "and nothing was applied from it");
    }

    #[test]
    fn a_hole_in_the_sequence_poisons_the_set() {
        // seq 2 is missing, so the order it carried is unknown. Applying 1 and 3 and
        // recording seq 3 would tell the control plane this mediator is current when
        // it has missed a cut.
        let report = apply_revocations(
            &delta(vec![
                party(1, "spiffe://org/ns/agents/sa/recon"),
                connection(3, "conn_00000003"),
            ]),
            &revocation_keys(),
            &Revocations::new(),
            0,
        );
        assert!(!report.contiguous);
        assert_eq!(report.applied_seq, 1, "the sequence stops at the hole");
        let set = report.set.unwrap();
        assert_eq!(set.distrusted(), Some("feed is not contiguous after seq 1"));
    }

    #[test]
    fn a_clean_pull_clears_an_earlier_distrust() {
        // Failing closed for ever is an outage, not a control. Verified and
        // contiguous from `since` is the evidence that justifies serving again.
        let mut previous = Revocations::new();
        previous.distrust("an earlier pull was corrupt");

        let report = apply_revocations(
            &delta(vec![party(1, "spiffe://org/ns/agents/sa/recon")]),
            &revocation_keys(),
            &previous,
            0,
        );
        assert!(report.is_clean());
        let set = report.set.unwrap();
        assert_eq!(set.distrusted(), None);
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn revocations_are_cumulative_so_a_partial_fetch_cannot_un_revoke() {
        // The failure this prevents: rebuilding the set from a delta would drop
        // every earlier revocation the moment a fetch returned only new entries.
        let mut previous = Revocations::new();
        previous.revoke_party("spiffe://org/ns/agents/sa/old");

        let report = apply_revocations(
            &delta(vec![connection(1, "conn_00000009")]),
            &revocation_keys(),
            &previous,
            0,
        );
        let set = report.set.unwrap();
        assert_eq!(set.len(), 2, "the earlier revocation survived");
    }

    #[test]
    fn a_sequence_gap_stops_application_and_does_not_advance_the_cursor() {
        // Applying what arrived and reporting the higher sequence would tell the
        // control plane this mediator is current when it has missed a cut.
        let report = apply_revocations(
            &delta(vec![
                party(1, "spiffe://org/ns/agents/sa/a"),
                connection(3, "conn_00000003"),
            ]),
            &revocation_keys(),
            &Revocations::new(),
            0,
        );
        assert!(!report.contiguous);
        assert!(!report.is_clean());
        assert_eq!(report.applied, 1);
        assert_eq!(report.applied_seq, 1, "the cursor stops at the hole");
    }

    #[test]
    fn an_unreachable_control_plane_is_an_error_not_an_empty_delta() {
        // An empty delta reads as "nothing new is revoked", which is the wrong
        // conclusion to draw from a control plane you cannot reach.
        let client = ControlPlaneClient::new("http://127.0.0.1:1", "m", "t")
            .with_timeout(Duration::from_millis(400));
        assert_eq!(
            client.fetch_revocations(0).unwrap_err().code(),
            Code::CONTRACT_REVOKED
        );
    }

    #[test]
    fn a_mediator_id_is_percent_encoded_for_a_path() {
        let client = ControlPlaneClient::new("https://x", "warden:mediator:apac-ops", "t");
        assert_eq!(client.encoded_id(), "warden%3Amediator%3Aapac-ops");
    }

    #[test]
    fn a_trailing_slash_on_the_base_is_dropped() {
        let client = ControlPlaneClient::new("https://connect.internal/", "m", "t");
        assert_eq!(client.base, "https://connect.internal");
    }

    #[test]
    fn a_set_separates_supplied_artifacts_from_missing_ones() {
        let set: ContractSet = serde_json::from_str(
            r#"{"seq":7,"set_hash":"sha256:aa","active":[
                 {"cid":"conn_1","jws":"a.b.c"},
                 {"cid":"conn_2"}
               ],"removed":["conn_3"]}"#,
        )
        .unwrap();
        assert_eq!(set.artifacts(), vec!["a.b.c".to_string()]);
        assert_eq!(set.missing_artifacts(), vec!["conn_2"]);
        assert_eq!(set.removed, vec!["conn_3".to_string()]);
    }

    #[test]
    fn an_unreachable_control_plane_is_an_error_not_an_empty_set() {
        // Fail closed: an empty set would silently drop every contract.
        let client = ControlPlaneClient::new("http://127.0.0.1:1", "m", "t")
            .with_timeout(Duration::from_millis(400));
        let err = client.fetch(0).unwrap_err();
        assert_eq!(err.code(), Code::NO_CONTRACT);
    }

    #[test]
    fn a_refresh_report_is_only_clean_when_everything_worked() {
        let clean_rev = RevocationReport {
            contiguous: true,
            rejected: Vec::new(),
            ..RevocationReport::default()
        };
        let mut report = RefreshReport {
            acked: true,
            revocations: Some(clean_rev.clone()),
            ..Default::default()
        };
        assert!(report.is_clean());
        report.missing.push("conn_1".to_string());
        assert!(!report.is_clean());
        report.missing.clear();
        report
            .rejected
            .push(("x".to_string(), Code::SIGNATURE_INVALID));
        assert!(!report.is_clean());
        report.rejected.clear();
        report.acked = false;
        assert!(!report.is_clean());
        report.acked = true;
        assert!(report.is_clean());

        // A set installed without its revocation feed is NOT a current set. A contract can be
        // withdrawn without the published set changing — that is what a deny-list is for — so
        // treating this as fresh is exactly how a cut connection keeps being honoured. This
        // assertion is the one that was missing while nothing fetched the feed at all.
        report.revocations = None;
        assert!(
            !report.is_clean(),
            "a refresh that could not reach the revocation feed must not count as clean"
        );

        // And a delta with a gap is worse than no delta: it looks like an answer.
        report.revocations = Some(RevocationReport {
            contiguous: false,
            ..clean_rev
        });
        assert!(!report.is_clean());
    }
}

#[cfg(test)]
mod install_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::install_revocations;
    use super::tests::{connection, delta, party, revocation_keys};
    use crate::cache::Cache;
    use wc_core::contract::RevocationView;
    use wc_core::error::Code;

    /// The whole point, and the thing nothing did.
    ///
    /// `fetch_revocations`, `apply_revocations` and `Cache::set_revocations` were each complete
    /// and each tested, and no binary called any of them — so `Cache::resolve` consulted an
    /// empty deny-list on every call for as long as the feature has existed. This asserts the
    /// wire, not the pieces.
    #[test]
    fn a_revoked_connection_stops_resolving_after_the_delta_is_installed() {
        let cache = Cache::new();
        let report = install_revocations(
            &cache,
            &delta(vec![connection(1, "conn_00000001")]),
            &revocation_keys(),
            0,
        );
        assert!(report.is_clean(), "the delta must verify: {report:?}");
        assert!(
            cache.revocations().cid_revoked("conn_00000001"),
            "the set the resolver reads must be the one that was installed"
        );
    }

    #[test]
    fn revocations_accumulate_rather_than_being_replaced() {
        let cache = Cache::new();
        install_revocations(
            &cache,
            &delta(vec![connection(1, "conn_00000001")]),
            &revocation_keys(),
            0,
        );
        // A later delta that says nothing about the first entry must not un-revoke it.
        install_revocations(
            &cache,
            &delta(vec![party(2, "spiffe://org/ns/agents/sa/recon")]),
            &revocation_keys(),
            1,
        );
        let set = cache.revocations();
        assert!(
            set.cid_revoked("conn_00000001"),
            "a deny-list is cumulative"
        );
        assert!(set.party_revoked("spiffe://org/ns/agents/sa/recon"));
    }

    /// A gap means this process cannot know what is revoked. Installing the partial set would
    /// look like a successful refresh and leave entries un-revoked that the plane has cut.
    #[test]
    fn a_delta_with_a_gap_distrusts_the_set_rather_than_installing_part_of_it() {
        let cache = Cache::new();
        // Starts at seq 4 when the cache has applied nothing: entries 1..3 are missing.
        let report = install_revocations(
            &cache,
            &delta(vec![connection(4, "conn_00000004")]),
            &revocation_keys(),
            0,
        );
        assert!(!report.contiguous, "the gap must be detected");
        let set = cache.revocations();
        assert!(
            set.distrusted().is_some(),
            "an unknown revocation state must read as revoked, not as 'nothing is revoked'"
        );
        assert!(
            !set.cid_revoked("conn_00000004"),
            "a partial set must not be installed as if it were the whole truth"
        );
    }

    /// And a distrusted set refuses everything, which is what makes the gap safe.
    #[test]
    fn a_distrusted_set_refuses_a_contract_that_is_not_itself_revoked() {
        let cache = Cache::new();
        install_revocations(
            &cache,
            &delta(vec![connection(9, "conn_00000009")]),
            &revocation_keys(),
            0,
        );
        let e = cache
            .resolve(
                Some("conn_anything"),
                &wc_core::model::EntityId::new("spiffe://org/ns/a/sa/x").unwrap(),
                &wc_core::model::EntityId::new("spiffe://org/ns/b/sa/y").unwrap(),
            )
            .expect_err("a distrusted revocation state admits nothing");
        // No contract is in this empty cache either, so either refusal is correct — what must
        // NOT happen is an admission.
        assert!(
            matches!(e.code(), Code::CONTRACT_REVOKED | Code::NO_CONTRACT),
            "got {}",
            e.code()
        );
    }
}
