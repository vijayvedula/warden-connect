//! What a consumer asks for, and whether an offer permits it (W2).
//!
//! The consumer's half of offer-and-acceptance. A [`NeedManifest`] lives in the *consumer's*
//! repository, reviewed by whoever owns it, and [`match_need`] decides whether the provider's
//! published [`crate::offer::Offer`] already permits it. When it does, both consents are on
//! record — the provider's from a reviewed commit in their repo, the consumer's from one in
//! theirs — and neither party ever reviewed the other's pull request.
//!
//! # Identity is derived, so idempotency is structural
//!
//! ```text
//! cid = conn_<H(consumer, provider)>              the connection
//! jti = cx_<H(cid, offer_version, scope, ttl)>    the artifact
//! ```
//!
//! Re-running a pipeline with the same *meaning* produces the same `jti`, so the mint is a
//! no-op. Nothing has to remember whether it ran: replay is impossible rather than detected,
//! which is stronger than the `idempotency-key` header the API uses for its own writes.
//!
//! Two decisions inside that are worth stating, because both were different in the first sketch:
//!
//! **`cid` does not include the scope.** One connection per party pair. A consumer who widens or
//! narrows what they need is changing *this* connection's terms, so the old artifact is
//! superseded under the same `cid` — which is what revocation and containment want to address.
//! Folding scope into `cid` would make every scope edit a brand-new connection and leave the old
//! one to expire on its own.
//!
//! **`jti` does not include the manifest digest.** It covers the *semantic* inputs. A commit that
//! reformats a comment resolves to the same scope and must not re-mint; a commit that adds a tool
//! must. The repo, sha and manifest digest are recorded on the contract as provenance — they say
//! where it came from without deciding what it is.
//!
//! # All or nothing
//!
//! A need asking for three items where the offer permits two is **refused**, and the refusal
//! names every item that failed and why. Issuing the two would hand back a contract nobody
//! asked for, and the consumer would discover the gap at runtime instead of in their pipeline.
//! Reporting all failures at once matters for the same reason: fixing them one per pipeline run
//! is a slow loop.

use std::collections::BTreeSet;

use serde::Deserialize;

use wc_core::error::{Code, Result, WcError};
use wc_core::model::{Cid, EntityId, Jti, Tier};
use wc_core::util::sha256_hex;

use crate::offer::{Offer, TermOutcome};

/// One entry in a consumer's manifest.
#[derive(Debug, Clone, Deserialize)]
pub struct NeedEntry {
    /// The provider's asset id.
    pub to: String,
    /// Items wanted.
    #[serde(default)]
    pub tools: Vec<String>,
    /// Why, in the consumer's own words. Recorded, never interpreted.
    pub justify: String,
    /// Requested TTL in seconds. The offer's term caps it.
    #[serde(default)]
    pub ttl: Option<u64>,
}

/// A consumer's `warden/connections.toml`.
#[derive(Debug, Clone, Deserialize)]
pub struct NeedManifest {
    /// The consuming party's id.
    pub asset: String,
    /// What it wants.
    #[serde(default, rename = "need")]
    pub needs: Vec<NeedEntry>,
}

impl NeedManifest {
    /// Parse a manifest.
    pub fn parse(text: &str) -> Result<NeedManifest> {
        toml::from_str(text).map_err(|e| {
            WcError::with_detail(Code::POLICY_INVALID, format!("need manifest: {e}")).with_source(e)
        })
    }

    /// Resolve one entry into a checkable [`Need`].
    pub fn resolve(&self, entry: &NeedEntry) -> Result<Need> {
        if entry.tools.is_empty() {
            return Err(WcError::with_detail(
                Code::POLICY_INVALID,
                format!(
                    "the need for {:?} lists no tools; an empty need reads as though it asks for \
                     something",
                    entry.to
                ),
            ));
        }
        if entry.justify.trim().is_empty() {
            return Err(WcError::with_detail(
                Code::POLICY_INVALID,
                "a need must carry a justification: it is the only part of a contract written by \
                 a human, and it is what an approver and an auditor read",
            ));
        }
        Ok(Need {
            consumer: EntityId::new(&self.asset)?,
            provider: EntityId::new(&entry.to)?,
            // A set, so `["b","a"]` and `["a","b"]` are the same need and derive the same
            // identity. Manifest ordering is not a decision anybody should be able to make.
            items: entry.tools.iter().cloned().collect(),
            justify: entry.justify.clone(),
            ttl_requested: entry.ttl.unwrap_or(DEFAULT_TTL),
        })
    }
}

/// TTL a need gets when it does not ask for one, in seconds (24h).
///
/// Short on purpose. A consumer who has not thought about lifetime should get the lifetime that
/// costs least if they were wrong, and the offer's `ttl_max` is a ceiling rather than a target.
pub const DEFAULT_TTL: u64 = 24 * 60 * 60;

/// A resolved request for a connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Need {
    /// The consuming party.
    pub consumer: EntityId,
    /// The providing party.
    pub provider: EntityId,
    /// Items wanted, ordered so identity does not depend on the manifest's ordering.
    pub items: BTreeSet<String>,
    /// The human justification.
    pub justify: String,
    /// Requested TTL, before the offer's cap.
    pub ttl_requested: u64,
}

/// A need an offer permits, with the identity and ceiling that follow from it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Matched {
    /// The connection id — derived from the pair alone.
    pub cid: Cid,
    /// The artifact id — derived from the semantic inputs.
    pub jti: Jti,
    /// The contracted items.
    pub items: BTreeSet<String>,
    /// The TTL that applies: the smaller of what was asked and what every matched term allows.
    pub ttl: u64,
    /// Which offer version permitted this, so a later upgrade can find what it affects.
    pub offer_version: u64,
    /// Contracted items the provider has scheduled for withdrawal, with the date, when the
    /// contract expires before it. Not a refusal — the contract is sound — but the consumer's
    /// *next* one may not be, and this is the only notice they get.
    pub deprecating: Vec<(String, u64)>,
}

impl Matched {
    /// The identity and offer version, as issuance wants them.
    ///
    /// A method rather than a caller assembling the struct field by field: the whole point of
    /// [`crate::issuance::Derived`] is that the version and the `jti` it is folded into cannot
    /// drift apart, and that only holds if one place builds it.
    #[must_use]
    pub fn derived(&self) -> crate::issuance::Derived {
        crate::issuance::Derived {
            cid: self.cid.clone(),
            jti: self.jti.clone(),
            offer_version: self.offer_version,
        }
    }
}

/// Why a need was refused, per item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemRefusal {
    /// The item.
    pub item: String,
    /// What the offer said about it, in words an operator can act on.
    pub why: String,
}

/// Derive the connection id for a pair.
///
/// Stable across scope and TTL changes: those supersede an artifact within the same connection.
#[must_use]
pub fn derive_cid(consumer: &EntityId, provider: &EntityId) -> Cid {
    let digest = sha256_hex(&format!("{}\n{}", consumer.as_str(), provider.as_str()));
    // 16 hex digits — well past the validator's 8-digit floor, and short enough to read in a
    // log line, which is where a `cid` is mostly seen.
    Cid::new(format!("conn_{}", &digest[..16])).unwrap_or_else(|_| {
        unreachable!("a sha256 prefix is always valid hex of the required length")
    })
}

/// Derive the artifact id from the inputs that decide what the artifact *is*.
#[must_use]
pub fn derive_jti(cid: &Cid, offer_version: u64, items: &BTreeSet<String>, ttl: u64) -> Jti {
    let scope = items.iter().cloned().collect::<Vec<_>>().join(",");
    let digest = sha256_hex(&format!(
        "{}\n{}\n{}\n{}",
        cid.as_str(),
        offer_version,
        scope,
        ttl
    ));
    Jti::new(format!("cx_{}", &digest[..24]))
        .unwrap_or_else(|_| unreachable!("a sha256 prefix is always valid for a jti"))
}

/// A deprecation date, rendered for an operator rather than as a Unix second.
///
/// `export::iso8601` rather than a second date implementation: it is already correct across the
/// awkward cases and has a test saying so, and two renderings of the same instant that disagree
/// is a bug waiting for a leap year.
fn on_day(after: u64) -> String {
    format!("{} (unix {after})", crate::export::iso8601(after))
}

/// Decide whether an offer permits a need.
///
/// `consumer_zone` and `consumer_tier` come from the consumer's registry record, never from its
/// manifest: a party that could assert its own zone could write itself into any audience.
pub fn match_need(
    need: &Need,
    offer: &Offer,
    consumer_zone: &str,
    consumer_tier: Tier,
    now: u64,
) -> std::result::Result<Matched, Vec<ItemRefusal>> {
    // The offer must be the provider's. Checked rather than assumed, because a caller holding
    // the wrong offer would otherwise contract against terms nobody published for this party.
    if offer.asset != need.provider {
        return Err(vec![ItemRefusal {
            item: String::new(),
            why: format!(
                "the offer belongs to {} and this need is for {}",
                offer.asset, need.provider
            ),
        }]);
    }

    let mut refusals = Vec::new();
    let mut ceiling = need.ttl_requested;
    let mut deprecating = Vec::new();

    for item in &need.items {
        match offer.permits(item, consumer_zone, consumer_tier) {
            TermOutcome::PreGranted { ttl_max } => ceiling = ceiling.min(ttl_max),
            TermOutcome::NeedsNamedApproval => refusals.push(ItemRefusal {
                item: item.clone(),
                why: "the provider requires per-consumer approval for this item, which is not \
                      wired yet; ask the provider's owner to add you, or drop it from the need"
                    .to_string(),
            }),
            TermOutcome::NotOffered { item_exists: true } => refusals.push(ItemRefusal {
                item: item.clone(),
                why: format!(
                    "offered, but not to a consumer in zone {consumer_zone} at tier \
                     {consumer_tier} — this is a conversation with the provider about their \
                     audience, not about the item"
                ),
            }),
            TermOutcome::NotOffered { item_exists: false } => refusals.push(ItemRefusal {
                item: item.clone(),
                why: "no term in the provider's offer covers this item at all".to_string(),
            }),
        }
    }

    // Withdrawal dates, applied after the TTL ceiling is known because that is what they are
    // compared against.
    //
    // Three cases, and the middle one is the design decision worth defending. A contract must
    // never outlive the item it names, so an offer that schedules an item for withdrawal has to
    // bound the contracts covering it. The obvious move is to *clamp* the TTL to `after - now`
    // — and it is wrong here, because `ttl` is folded into the derived `jti`. A ceiling that
    // shrinks with the clock gives every build in the final window a different artifact id, so
    // an unchanged pipeline re-mints on every run, the contract set churns, and the mediator
    // refreshes for nothing. The idempotency this whole derivation exists for would hold only
    // until a provider deprecated something.
    //
    // So it refuses instead, naming the largest TTL that fits. The consumer edits one line of
    // their manifest and their next build is stable again — and the refusal is the deprecation
    // notice actually arriving, which a silent shortening would not be.
    for item in &need.items {
        let Some(after) = offer.deprecated_after(item) else {
            continue;
        };
        if now >= after {
            refusals.push(ItemRefusal {
                item: item.clone(),
                why: format!(
                    "the provider withdrew this item on {} — it is still listed in a term, and the \
                     withdrawal date is what governs, or the schedule would be decorative",
                    on_day(after)
                ),
            });
        } else if now.saturating_add(ceiling) > after {
            refusals.push(ItemRefusal {
                item: item.clone(),
                why: format!(
                    "the provider withdraws this item on {}, and a contract at the current ceiling \
                     of {ceiling}s would outlive it. Lower `ttl` in your need to at most {}s, or \
                     drop the item. Not shortened for you: the TTL is folded into the artifact \
                     id, so a ceiling that moved with the clock would re-mint on every build",
                    on_day(after),
                    after - now
                ),
            });
        } else {
            deprecating.push((item.clone(), after));
        }
    }

    // All or nothing. A partial contract is one the consumer did not ask for.
    if !refusals.is_empty() {
        return Err(refusals);
    }

    let cid = derive_cid(&need.consumer, &need.provider);
    let jti = derive_jti(&cid, offer.version, &need.items, ceiling);
    Ok(Matched {
        cid,
        jti,
        items: need.items.clone(),
        ttl: ceiling,
        offer_version: offer.version,
        deprecating,
    })
}

/// A refusal list as one error, for a caller that just needs to fail a pipeline.
#[must_use]
pub fn refusal_error(need: &Need, refusals: &[ItemRefusal]) -> WcError {
    let detail = refusals
        .iter()
        .map(|r| {
            if r.item.is_empty() {
                r.why.clone()
            } else {
                format!("{}: {}", r.item, r.why)
            }
        })
        .collect::<Vec<_>>()
        .join("; ");
    WcError::with_detail(
        Code::POLICY_DENIED,
        format!(
            "{} may not contract {} — {detail}",
            need.consumer, need.provider,
        ),
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use crate::offer::{Deprecation, OfferManifest, OfferSource};
    use wc_core::canon::SurfaceKind;

    const CONSUMER: &str = "spiffe://bank/ns/agents/sa/recon-bot";
    const PROVIDER: &str = "spiffe://bank/ns/svc/sa/payments-mcp";

    /// A fixed clock. Deprecation dates in these fixtures are relative to it.
    const NOW: u64 = 1_785_312_500;

    fn tier(n: u8) -> Tier {
        Tier::new(n).unwrap()
    }

    fn declared() -> BTreeSet<String> {
        ["get_balance", "list_transactions", "transfer_funds"]
            .into_iter()
            .map(String::from)
            .collect()
    }

    fn offer(version: u64) -> Offer {
        let text = format!(
            r#"
asset = "{PROVIDER}"

[[term]]
items = ["get_balance", "list_transactions"]
approval = "pre_granted"
ttl_max = 604800
to = {{ zone = "internal.*" }}

[[term]]
items = ["transfer_funds"]
approval = "named_consumer"
ttl_max = 3600
"#
        );
        OfferManifest::parse(&text)
            .unwrap()
            .into_offer(
                &declared(),
                SurfaceKind::McpTools,
                "sha256:ffff",
                version,
                OfferSource {
                    repo: "bank/payments-mcp".into(),
                    sha: "abc".into(),
                    manifest_digest: "sha256:aaaa".into(),
                },
            )
            .unwrap()
    }

    fn need_of(tools: &[&str], ttl: Option<u64>) -> Need {
        let list = tools
            .iter()
            .map(|t| format!("\"{t}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let ttl_line = ttl.map_or(String::new(), |t| format!("ttl = {t}\n"));
        let text = format!(
            "asset = \"{CONSUMER}\"\n\n[[need]]\nto = \"{PROVIDER}\"\ntools = [{list}]\n\
             justify = \"APAC reconciliation\"\n{ttl_line}"
        );
        let m = NeedManifest::parse(&text).unwrap();
        m.resolve(&m.needs[0]).unwrap()
    }

    /// An offer whose `get_balance` term deprecates the item at `after`.
    fn offer_deprecating(version: u64, after: u64) -> Offer {
        let mut o = offer(version);
        o.terms[0].deprecates = vec![Deprecation {
            item: "get_balance".into(),
            after,
        }];
        o
    }

    #[test]
    fn a_withdrawal_date_already_passed_refuses_the_item() {
        // The term still lists it. The date governs anyway, or a deprecation schedule is a
        // comment: a provider who published a removal date and then forgot to edit the term
        // would keep issuing contracts for something they consider gone.
        let refusals = match_need(
            &need_of(&["get_balance"], Some(3_600)),
            &offer_deprecating(1, NOW - 1),
            "internal.apac",
            tier(2),
            NOW,
        )
        .unwrap_err();
        assert_eq!(refusals.len(), 1);
        assert_eq!(refusals[0].item, "get_balance");
        assert!(refusals[0].why.contains("withdrew"), "{}", refusals[0].why);
    }

    #[test]
    fn a_contract_that_would_outlive_a_withdrawal_is_refused_not_shortened() {
        // Refused rather than clamped, and this test is the reason. `ttl` is folded into the
        // derived `jti`, so a ceiling of `after - now` would give every build in the final
        // window a different artifact id: an unchanged pipeline would re-mint on every run and
        // the contract set would churn. The refusal names the TTL that fits, so the fix is one
        // line of the consumer's manifest and the next build is stable again.
        let after = NOW + 3_600;
        let refusals = match_need(
            &need_of(&["get_balance"], Some(7_200)),
            &offer_deprecating(1, after),
            "internal.apac",
            tier(2),
            NOW,
        )
        .unwrap_err();
        assert_eq!(refusals.len(), 1);
        assert!(refusals[0].why.contains("3600s"), "{}", refusals[0].why);

        // Inside the window it is permitted, and reported rather than silent — the consumer's
        // pipeline is the only place the provider's withdrawal date reaches them.
        let m = match_need(
            &need_of(&["get_balance"], Some(1_800)),
            &offer_deprecating(1, after),
            "internal.apac",
            tier(2),
            NOW,
        )
        .expect("a contract that expires before the withdrawal is fine");
        assert_eq!(m.ttl, 1_800);
        assert_eq!(m.deprecating, vec![("get_balance".to_string(), after)]);

        // And the identity does not move with the clock, which is the property the refusal
        // exists to protect. Ten minutes later, same build, same artifact id.
        let later = match_need(
            &need_of(&["get_balance"], Some(1_800)),
            &offer_deprecating(1, after),
            "internal.apac",
            tier(2),
            NOW + 600,
        )
        .expect("still inside the window");
        assert_eq!(later.jti, m.jti, "the derived jti moved with the clock");
    }

    #[test]
    fn an_item_with_no_withdrawal_date_reports_nothing() {
        let m = match_need(
            &need_of(&["get_balance"], Some(3_600)),
            &offer(1),
            "internal.apac",
            tier(2),
            NOW,
        )
        .expect("permitted");
        assert!(m.deprecating.is_empty());
    }

    #[test]
    fn a_need_inside_the_offer_is_contractable() {
        let m = match_need(
            &need_of(&["get_balance"], None),
            &offer(7),
            "internal.apac",
            tier(2),
            NOW,
        )
        .expect("permitted");
        assert_eq!(m.offer_version, 7);
        assert!(m.cid.as_str().starts_with("conn_"));
        assert!(m.jti.as_str().starts_with("cx_"));
    }

    #[test]
    fn the_offer_caps_a_longer_requested_ttl() {
        // Asked for 30 days, the term allows 7. The ceiling wins — a need cannot talk its way
        // past a provider's limit.
        let m = match_need(
            &need_of(&["get_balance"], Some(2_592_000)),
            &offer(1),
            "internal.apac",
            tier(2),
            NOW,
        )
        .unwrap();
        assert_eq!(m.ttl, 604_800);
    }

    #[test]
    fn a_shorter_requested_ttl_is_respected_rather_than_raised_to_the_ceiling() {
        let m = match_need(
            &need_of(&["get_balance"], Some(3_600)),
            &offer(1),
            "internal.apac",
            tier(2),
            NOW,
        )
        .unwrap();
        assert_eq!(m.ttl, 3_600, "ttl_max is a ceiling, not a target");
    }

    #[test]
    fn manifest_ordering_does_not_change_the_derived_identity() {
        // Otherwise re-ordering a list in a manifest would mint a new contract, and the
        // "same inputs, same artifact" property would depend on how somebody typed it.
        let a = match_need(
            &need_of(&["get_balance", "list_transactions"], None),
            &offer(3),
            "internal.apac",
            tier(2),
            NOW,
        )
        .unwrap();
        let b = match_need(
            &need_of(&["list_transactions", "get_balance"], None),
            &offer(3),
            "internal.apac",
            tier(2),
            NOW,
        )
        .unwrap();
        assert_eq!(a.jti, b.jti);
        assert_eq!(a.cid, b.cid);
    }

    #[test]
    fn the_same_semantic_inputs_derive_the_same_artifact_so_a_re_run_is_a_no_op() {
        let first = match_need(
            &need_of(&["get_balance"], None),
            &offer(4),
            "internal.apac",
            tier(2),
            NOW,
        )
        .unwrap();
        let again = match_need(
            &need_of(&["get_balance"], None),
            &offer(4),
            "internal.apac",
            tier(2),
            NOW,
        )
        .unwrap();
        assert_eq!(
            first.jti, again.jti,
            "idempotency is structural, not bookkeeping"
        );
    }

    #[test]
    fn a_new_offer_version_derives_a_new_artifact_under_the_same_connection() {
        // The upgrade path: the provider republishes, the artifact changes, the connection does
        // not — so a supersede addresses the same `cid` a revocation would.
        let old = match_need(
            &need_of(&["get_balance"], None),
            &offer(6),
            "internal.apac",
            tier(2),
            NOW,
        )
        .unwrap();
        let new = match_need(
            &need_of(&["get_balance"], None),
            &offer(7),
            "internal.apac",
            tier(2),
            NOW,
        )
        .unwrap();
        assert_eq!(
            old.cid, new.cid,
            "the connection is the pair, not the terms"
        );
        assert_ne!(old.jti, new.jti, "a new offer version is a new artifact");
    }

    #[test]
    fn widening_the_scope_supersedes_within_the_same_connection() {
        let narrow = match_need(
            &need_of(&["get_balance"], None),
            &offer(1),
            "internal.apac",
            tier(2),
            NOW,
        )
        .unwrap();
        let wide = match_need(
            &need_of(&["get_balance", "list_transactions"], None),
            &offer(1),
            "internal.apac",
            tier(2),
            NOW,
        )
        .unwrap();
        assert_eq!(narrow.cid, wide.cid);
        assert_ne!(narrow.jti, wide.jti);
    }

    #[test]
    fn a_named_consumer_item_refuses_the_whole_need_rather_than_issuing_the_rest() {
        // Partial issuance would hand back a contract the consumer did not ask for, and the
        // gap would surface at runtime instead of in the pipeline.
        let refusals = match_need(
            &need_of(&["get_balance", "transfer_funds"], None),
            &offer(1),
            "internal.apac",
            tier(2),
            NOW,
        )
        .expect_err("must refuse");
        assert_eq!(refusals.len(), 1);
        assert_eq!(refusals[0].item, "transfer_funds");
        assert!(
            refusals[0].why.contains("per-consumer approval"),
            "{:?}",
            refusals[0]
        );
    }

    #[test]
    fn every_failing_item_is_reported_at_once_not_one_per_pipeline_run() {
        let refusals = match_need(
            &need_of(&["transfer_funds", "nonexistent"], None),
            &offer(1),
            "internal.apac",
            tier(2),
            NOW,
        )
        .expect_err("must refuse");
        assert_eq!(refusals.len(), 2, "{refusals:?}");
    }

    #[test]
    fn an_out_of_audience_consumer_is_told_it_is_about_the_audience() {
        // "Not offered to you" and "not offered at all" send an operator to different people.
        let refusals = match_need(
            &need_of(&["get_balance"], None),
            &offer(1),
            "partner.acme",
            tier(2),
            NOW,
        )
        .expect_err("must refuse");
        assert!(refusals[0].why.contains("audience"), "{:?}", refusals[0]);

        let unknown = match_need(
            &need_of(&["nonexistent"], None),
            &offer(1),
            "internal.apac",
            tier(2),
            NOW,
        )
        .expect_err("must refuse");
        assert!(unknown[0].why.contains("at all"), "{:?}", unknown[0]);
    }

    #[test]
    fn an_offer_belonging_to_a_different_provider_is_refused() {
        // A caller holding the wrong offer would otherwise contract against terms nobody
        // published for this party.
        let mut wrong = offer(1);
        wrong.asset = EntityId::new("spiffe://bank/ns/svc/sa/somebody-else").unwrap();
        let refusals = match_need(
            &need_of(&["get_balance"], None),
            &wrong,
            "internal.apac",
            tier(2),
            NOW,
        )
        .expect_err("must refuse");
        assert!(refusals[0].why.contains("belongs to"), "{:?}", refusals[0]);
    }

    #[test]
    fn a_need_with_no_tools_or_no_justification_is_refused_at_parse_time() {
        let no_tools = format!(
            "asset = \"{CONSUMER}\"\n[[need]]\nto = \"{PROVIDER}\"\ntools = []\njustify = \"x\"\n"
        );
        let m = NeedManifest::parse(&no_tools).unwrap();
        assert_eq!(
            m.resolve(&m.needs[0]).unwrap_err().code(),
            Code::POLICY_INVALID
        );

        let no_why = format!(
            "asset = \"{CONSUMER}\"\n[[need]]\nto = \"{PROVIDER}\"\ntools = [\"get_balance\"]\n\
             justify = \"   \"\n"
        );
        let m = NeedManifest::parse(&no_why).unwrap();
        assert_eq!(
            m.resolve(&m.needs[0]).unwrap_err().code(),
            Code::POLICY_INVALID
        );
    }

    #[test]
    fn the_default_ttl_is_short_because_an_unconsidered_lifetime_should_cost_least() {
        let m = match_need(
            &need_of(&["get_balance"], None),
            &offer(1),
            "internal.apac",
            tier(2),
            NOW,
        )
        .unwrap();
        assert_eq!(m.ttl, DEFAULT_TTL);

        // Compared against the offer's own ceiling rather than a literal: two constants would
        // be a compile-time tautology, and what actually matters is that a need which asked for
        // nothing lands well below what the provider was willing to allow.
        let term_ceiling = offer(1)
            .terms
            .iter()
            .filter(|t| t.items.iter().any(|i| i == "get_balance"))
            .map(|t| t.ttl_max)
            .min()
            .expect("the term exists");
        assert!(
            m.ttl < term_ceiling,
            "the default {} must sit below the term's ceiling {term_ceiling}",
            m.ttl
        );
    }

    #[test]
    fn a_refusal_renders_as_one_error_a_pipeline_can_fail_on() {
        let need = need_of(&["transfer_funds"], None);
        let refusals = match_need(&need, &offer(1), "internal.apac", tier(2), NOW).unwrap_err();
        let err = refusal_error(&need, &refusals);
        assert_eq!(err.code(), Code::POLICY_DENIED);
        assert!(err.detail().contains("transfer_funds"), "{}", err.detail());
    }
}
