//! What a provider makes available, and to whom (W1).
//!
//! A contract needs **offer and acceptance**. Before this module there was only acceptance:
//! `request` + `approve` recorded that somebody wanted a connection and that an approver with a
//! role signed for it, and nothing anywhere recorded what the *callee's* owners had agreed to
//! expose. An entity had a surface and no terms of availability, so "a contract between two
//! parties" was one party's request blessed by a central approver.
//!
//! An [`Offer`] is the missing half. The provider publishes it **from its own repository**,
//! reviewed by whoever owns that repository, and the control plane holds it until a consumer's
//! need turns up. The two consents therefore arrive at different times through different
//! pipelines and meet in the registry — which is why no consumer ever needs the provider's
//! reviewers on their pull request.
//!
//! # Strictest term wins, not first match
//!
//! `cpolicy` learned this the expensive way: a money-movement rule sat *below* a generic tier
//! rule, so its spend cap and blocking evidence never applied to a payments contract. Ordering
//! was load-bearing and invisible.
//!
//! So an offer's terms are **unordered**, and when several cover the same item the strictest
//! one applies. Moving a term up or down a file cannot change a decision, which removes the
//! entire class of defect rather than documenting it.
//!
//! # What an offer is not
//!
//! Not a grant. A term says *"this item may be contracted by a consumer of this shape"* — the
//! contract still has to be minted, the consumer still has to accept in its own repository, and
//! `effective = contract.surface ∩ token.scope ∩ policy_decision` is unchanged. An offer only
//! ever *permits the asking*.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use wc_core::canon::SurfaceKind;
use wc_core::contract::{ContractRecord, IssuerKey};
use wc_core::error::{Code, Result, WcError};
use wc_core::model::{EntityId, Tier};

use crate::cpolicy::{Glob, TierMatch};

/// Longest TTL any term may grant, in seconds (30 days).
///
/// A ceiling on the ceiling. A provider that writes `ttl_max = "10y"` has not made a decision,
/// it has opted out of expiry — and expiry is the containment bound of last resort when a
/// mediator cannot be reached (`docs/limitations.md`).
pub const TTL_MAX_CEILING: u64 = 30 * 24 * 60 * 60;

/// How a term expects a consumer to be approved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TermApproval {
    /// The offer itself is the provider's consent, for any consumer matching the audience.
    ///
    /// The provider's owners approved a *class*, once, in a reviewed commit. That is a stronger
    /// artifact than a per-consumer ticket rubber-stamped fifty times, which is what
    /// per-request approval degrades into at scale.
    PreGranted,
    /// This item needs the provider's explicit sign-off for each named consumer.
    ///
    /// Legitimate, and **not wired in the MVP**. A need that lands here is refused rather than
    /// quietly treated as pre-granted, which would turn the most sensitive terms into the most
    /// permissive ones.
    NamedConsumer,
}

/// Who a term is open to.
///
/// Both fields absent means "any consumer", which is a real thing to write for a read-only
/// tool — and is why the fields are `Option` rather than defaulted to something restrictive
/// that would silently narrow an offer the provider believed was open.
#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize)]
#[serde(default)]
pub struct Audience {
    /// Consumer zone glob.
    pub zone: Option<Glob>,
    /// Consumer tier constraint.
    pub tier: Option<TierMatch>,
}

impl Audience {
    /// Whether a consumer of this zone and tier is in scope.
    ///
    /// Takes a [`Tier`] rather than a `u8`: `Tier::new` rejects anything outside 1..=4, and
    /// accepting a raw integer here would let an out-of-range tier be compared as though it
    /// were a real one.
    #[must_use]
    pub fn admits(&self, zone: &str, tier: Tier) -> bool {
        self.zone.as_ref().is_none_or(|g| g.matches(zone))
            && self.tier.as_ref().is_none_or(|t| t.matches(tier))
    }
}

/// An item being withdrawn, with the date after which it is gone.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Deprecation {
    /// The item.
    pub item: String,
    /// Unix seconds after which the provider intends to remove it.
    pub after: u64,
}

/// One grant of availability.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Term {
    /// Items this term covers — tool names, skill ids, resource patterns.
    pub items: Vec<String>,
    /// Who may contract them.
    #[serde(default)]
    pub to: Audience,
    /// How a consumer is approved.
    pub approval: TermApproval,
    /// Longest TTL a contract under this term may carry, in seconds.
    pub ttl_max: u64,
    /// Items on the way out.
    #[serde(default)]
    pub deprecates: Vec<Deprecation>,
}

impl Term {
    /// How strict this term is. Higher is stricter, and the highest wins.
    fn strictness(&self) -> u8 {
        match self.approval {
            TermApproval::NamedConsumer => 1,
            TermApproval::PreGranted => 0,
        }
    }
}

/// Where an offer came from, so a contract is auditable back to a reviewed commit.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct OfferSource {
    /// Opaque repository identifier.
    ///
    /// **Never parsed.** Azure Repos is `org/project/repo`, GitLab nests arbitrarily and
    /// Bitbucket addresses by UUID; anything here that assumed a two-part path would break on
    /// three of four supported hosts. The asset registration maps the whole string.
    pub repo: String,
    /// The commit the manifest was read at.
    pub sha: String,
    /// Digest of the manifest bytes, so the contract records *what* was reviewed.
    pub manifest_digest: String,
}

/// One provider's offer, reduced to what a single consumer may see.
///
/// Built only by [`Offer::as_seen_by`], which is what guarantees nothing in here was visible to
/// somebody outside the audience the provider named.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CatalogueEntry {
    /// The provider.
    pub asset: EntityId,
    /// The offer version this view was taken from.
    pub version: u64,
    /// What kind of surface the items are.
    pub surface_kind: SurfaceKind,
    /// The surface the provider pinned, so a consumer can see it matches what they were told.
    pub surface_digest: String,
    /// Items contractable now: the offer itself is the provider's consent.
    pub pre_granted: Vec<String>,
    /// Items this consumer may **ask** for, decided per consumer by the provider's owner.
    pub needs_approval: Vec<String>,
    /// Visible items with a withdrawal date still ahead.
    pub withdrawing: Vec<(String, u64)>,
    /// Whether the publishing merge was verified against the source host.
    ///
    /// Shown because it changes what a consumer can do with the row, not merely how much to trust
    /// it: a need cannot be minted against an offer carrying no verified consent, so a catalogue
    /// that hid this would advertise items that refuse at the last step.
    pub consented: bool,
}

/// A provider's published terms of availability.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Offer {
    /// The providing party.
    pub asset: EntityId,
    /// Monotonic per provider. A new surface or new terms is a new version.
    pub version: u64,
    /// What kind of surface the digest covers.
    pub surface_kind: SurfaceKind,
    /// The pin over the provider's full declared surface.
    pub surface_digest: String,
    /// Unordered — see the module note on strictest-wins.
    pub terms: Vec<Term>,
    /// The reviewed commit this came from.
    pub source: OfferSource,
    /// The provider's consent, when the publishing merge was verified against the source host.
    ///
    /// `None` means the offer was recorded on the publisher's word alone. That is acceptable for
    /// a catalogue, and **not** acceptable as one half of a bilateral contract — so a need cannot
    /// be minted against an offer that carries no consent. Optional rather than required because
    /// the two facts are genuinely separable: an operator may want the terms on record before the
    /// shim for that host has been probed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consent: Option<wc_core::contract::MergeApproval>,
}

/// What an offer says about one requested item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TermOutcome {
    /// Contractable now; the provider's consent is the offer itself.
    PreGranted {
        /// The TTL ceiling that applies.
        ttl_max: u64,
    },
    /// Covered, but needs the provider's per-consumer sign-off.
    ///
    /// Carries the ceiling because the eventual contract is bound by the same term that gated
    /// it. Without the TTL here the approval path would have to re-find the term, and a second
    /// lookup that disagreed with the first is exactly the drift `strictness` exists to prevent.
    NeedsNamedApproval {
        /// The TTL ceiling that applies if the provider approves.
        ttl_max: u64,
    },
    /// No term covers this item for this consumer.
    NotOffered {
        /// Whether some term covers the item but not this audience, which is a different
        /// conversation with the provider than "that item is not offered at all".
        item_exists: bool,
    },
}

impl Offer {
    /// Attach the provider's verified consent.
    #[must_use]
    pub fn with_consent(mut self, consent: wc_core::contract::MergeApproval) -> Offer {
        self.consent = Some(consent);
        self
    }

    /// What this offer permits for one item and one consumer.
    ///
    /// Strictest term wins, so the answer does not depend on the order terms were written in.
    pub fn permits(&self, item: &str, consumer_zone: &str, consumer_tier: Tier) -> TermOutcome {
        let mut best: Option<&Term> = None;
        let mut item_exists = false;

        for term in &self.terms {
            if !term.items.iter().any(|i| i == item) {
                continue;
            }
            item_exists = true;
            if !term.to.admits(consumer_zone, consumer_tier) {
                continue;
            }
            match best {
                Some(b) if b.strictness() >= term.strictness() => {}
                _ => best = Some(term),
            }
        }

        match best {
            Some(t) => match t.approval {
                TermApproval::PreGranted => TermOutcome::PreGranted { ttl_max: t.ttl_max },
                TermApproval::NamedConsumer => {
                    TermOutcome::NeedsNamedApproval { ttl_max: t.ttl_max }
                }
            },
            None => TermOutcome::NotOffered { item_exists },
        }
    }

    /// This offer as one consumer sees it, or `None` if they see nothing.
    ///
    /// `None` rather than an entry with empty lists, and that is the whole security property. A
    /// consumer who is in no term's audience learns **nothing** — not that the asset exists, not
    /// that it offers something to somebody else. `connect discover` exists because a freely
    /// readable catalogue lets any registered party map the estate; this keeps that property while
    /// giving a consumer a browsable view, because everything it shows them is something the
    /// provider already consented to expose *to their audience*.
    ///
    /// `zone` and `tier` must come from the consumer's registry record, never from anything the
    /// consumer asserts — a party that could state its own zone could read itself into any
    /// audience. Same rule as [`crate::need::match_need`], same reason.
    #[must_use]
    pub fn as_seen_by(&self, zone: &str, tier: Tier, now: u64) -> Option<CatalogueEntry> {
        let mut pre_granted = Vec::new();
        let mut needs_approval = Vec::new();
        let mut withdrawing = Vec::new();

        // Deduplicated: an item may appear in several terms, and `permits` already resolves which
        // one governs. Listing it twice would suggest two different answers.
        let mut items: Vec<&str> = self
            .terms
            .iter()
            .flat_map(|t| t.items.iter().map(String::as_str))
            .collect();
        items.sort_unstable();
        items.dedup();

        for item in items {
            match self.permits(item, zone, tier) {
                TermOutcome::PreGranted { .. } => pre_granted.push(item.to_string()),
                TermOutcome::NeedsNamedApproval { .. } => needs_approval.push(item.to_string()),
                // Not shown at all, including `item_exists: true`. That an item is offered to some
                // other audience is not this consumer's business.
                TermOutcome::NotOffered { .. } => continue,
            }
            // Only for items they can see, and only dates still ahead: a date already passed means
            // the item is gone, and advertising it would invite a request `match_need` refuses.
            if let Some(after) = self.deprecated_after(item) {
                if after > now {
                    withdrawing.push((item.to_string(), after));
                }
            }
        }

        if pre_granted.is_empty() && needs_approval.is_empty() {
            return None;
        }
        Some(CatalogueEntry {
            asset: self.asset.clone(),
            version: self.version,
            surface_kind: self.surface_kind,
            surface_digest: self.surface_digest.clone(),
            pre_granted,
            needs_approval,
            withdrawing,
            consented: self.consent.is_some(),
        })
    }

    /// When an item is due to be withdrawn, if any term says so.
    ///
    /// Earliest date across terms: if one term deprecates an item sooner than another, the
    /// sooner date is the one a consumer has to plan around.
    #[must_use]
    pub fn deprecated_after(&self, item: &str) -> Option<u64> {
        self.terms
            .iter()
            .flat_map(|t| &t.deprecates)
            .filter(|d| d.item == item)
            .map(|d| d.after)
            .min()
    }

    /// Every item this offer mentions, across all terms.
    #[must_use]
    pub fn offered_items(&self) -> BTreeSet<String> {
        self.terms
            .iter()
            .flat_map(|t| t.items.iter().cloned())
            .collect()
    }
}

/// An offer as authored in `warden/offer.toml`, before it is checked against a surface.
///
/// TOML rather than YAML: `toml` is already a dependency and a YAML parser would be a new one
/// for no gain (§8.3). It also matches `connect-policy.toml`, so an operator reads one syntax.
#[derive(Debug, Clone, Deserialize)]
pub struct OfferManifest {
    /// The providing party's id.
    pub asset: String,
    /// The terms.
    #[serde(default, rename = "term")]
    pub terms: Vec<Term>,
}

impl OfferManifest {
    /// Parse a manifest.
    pub fn parse(text: &str) -> Result<OfferManifest> {
        toml::from_str(text).map_err(|e| {
            WcError::with_detail(Code::POLICY_INVALID, format!("offer manifest: {e}"))
                .with_source(e)
        })
    }

    /// Check the manifest against the provider's declared surface and build the offer.
    ///
    /// `declared` is the item set the surface actually contains. Validating against it is the
    /// point: a term naming an item the server does not declare is a term nobody can ever use,
    /// and silently keeping it means a provider believes they have published something they
    /// have not.
    pub fn into_offer(
        self,
        declared: &BTreeSet<String>,
        surface_kind: SurfaceKind,
        surface_digest: &str,
        version: u64,
        source: OfferSource,
    ) -> Result<Offer> {
        let asset = EntityId::new(&self.asset)?;
        if self.terms.is_empty() {
            return Err(WcError::with_detail(
                Code::POLICY_INVALID,
                "an offer with no terms offers nothing; omit the file instead of publishing an \
                 empty one, so the difference between 'not onboarded' and 'nothing available' \
                 stays visible",
            ));
        }

        for term in &self.terms {
            if term.items.is_empty() {
                return Err(WcError::with_detail(
                    Code::POLICY_INVALID,
                    "a term with no items grants nothing and reads as though it grants something",
                ));
            }
            if term.ttl_max == 0 || term.ttl_max > TTL_MAX_CEILING {
                return Err(WcError::with_detail(
                    Code::POLICY_INVALID,
                    format!(
                        "ttl_max must be between 1 and {TTL_MAX_CEILING} seconds, got {}; expiry \
                         is the containment bound when a mediator cannot be reached",
                        term.ttl_max
                    ),
                ));
            }
            for item in &term.items {
                if !declared.contains(item) {
                    return Err(WcError::with_detail(
                        Code::SURFACE_NOT_SUBSET,
                        format!(
                            "term offers {item:?}, which the declared surface does not contain; \
                             a term nobody can use is worse than no term, because the provider \
                             believes it is published"
                        ),
                    ));
                }
            }
            for dep in &term.deprecates {
                if !term.items.contains(&dep.item) {
                    return Err(WcError::with_detail(
                        Code::POLICY_INVALID,
                        format!(
                            "deprecates {:?}, which this term does not offer; a deprecation \
                             notice on an item nobody was given is a notice nobody receives",
                            dep.item
                        ),
                    ));
                }
            }
        }

        Ok(Offer {
            asset,
            version,
            surface_kind,
            surface_digest: surface_digest.to_string(),
            terms: self.terms,
            source,
            consent: None,
        })
    }
}

/// Attest a declared surface, so §8.7.1 stage 3 can pass.
///
/// # Why this exists
///
/// `Posture::Attested` requires `identity.verified && card.verified && provenance.verified`, and
/// `JwksCardVerifier` reports `verified: false` for a document with no `signatures` field. So a
/// server registered from a plain `surface.json` was permanently `Unattested`, and `WC-3109` is
/// `ClosedUnlessObserve` — **enforce mode refused every call**. That is why
/// `scripts/rotation-drill.sh` ran in observe, and it made enforce mode unreachable for every
/// real MCP server, since MCP has no convention for signing a `tools/list` result.
///
/// The requirement is right: the surface is what a contract pins, so an *unsigned* surface is
/// one anyone could have supplied, and treating it as attested would make the pin vouch for
/// nothing. What was missing was a signer with standing to make the claim.
///
/// The offer flow supplies one. The provider's pipeline authenticates with its own workload
/// identity and the merge is verified against the source host, so the plane can sign the
/// surface it accepted — attesting *"this arrived from the provider's reviewed commit"*. That is
/// a stronger claim than a card key handed to a tool team, and it needs no key in CI.
///
/// The signature is a detached-payload JWS over the canonical document with `signatures`
/// removed, which is the shape `JwksCardVerifier` already verifies. Nothing about the verifier
/// changes — the gap was that nobody produced the input it wanted.
pub fn attest_surface(document: &Value, key: &IssuerKey) -> Result<Value> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;

    if !document.is_object() {
        return Err(WcError::with_detail(
            Code::CONFIG_INVALID,
            "a surface attestation covers a JSON object; `signatures` has nowhere to live on \
             anything else",
        ));
    }

    let protected = URL_SAFE_NO_PAD.encode(
        serde_json::json!({ "alg": format!("{:?}", key.alg()), "kid": key.kid() }).to_string(),
    );
    let payload = URL_SAFE_NO_PAD.encode(crate::attest::card_signing_input(document).as_bytes());
    let signature =
        URL_SAFE_NO_PAD.encode(key.sign_raw(format!("{protected}.{payload}").as_bytes())?);

    // Appended, not replaced. `attest.rs` verifies each signature independently and treats one
    // trusted signature as the whole claim, so a provider that signs its own surface keeps that
    // signature when the plane counter-signs. Replacing would silently discard the stronger of
    // the two claims — and it is only safe to append *because* `signatures` is excluded from the
    // signed bytes, which is the property the re-attestation test below pins.
    let mut signed = document.clone();
    if let Some(obj) = signed.as_object_mut() {
        let entry = serde_json::json!({ "protected": protected, "signature": signature });
        match obj
            .get_mut(crate::attest::CARD_SIGNATURES_FIELD)
            .and_then(Value::as_array_mut)
        {
            Some(existing) => existing.push(entry),
            None => {
                obj.insert(
                    crate::attest::CARD_SIGNATURES_FIELD.to_string(),
                    serde_json::json!([entry]),
                );
            }
        }
    }
    Ok(signed)
}

// ---------------------------------------------------------------------------
// The upgrade question (W7)
// ---------------------------------------------------------------------------

/// One live contract, judged against the offer version now in force.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Affected {
    /// The connection.
    pub cid: String,
    /// Who holds it.
    pub consumer: EntityId,
    /// The offer version it was minted under. `None` means a human requested it directly rather
    /// than a pipeline matching a need, which is a different kind of contract and not a gap.
    pub minted_under: Option<u64>,
    /// When it lapses on its own.
    pub exp: u64,
    /// Contracted items the current offer no longer covers for this consumer at all. The most
    /// serious row: the provider's intent and the contract have diverged with no schedule
    /// between them.
    pub gone: Vec<String>,
    /// Contracted items the provider has moved behind per-consumer approval.
    ///
    /// Kept apart from [`Affected::gone`] deliberately. Before named approval was routed
    /// anywhere, a term that asked for it was unusable and reporting the item as gone was
    /// accurate. It is not accurate now: the consumer's next build becomes a request this
    /// provider decides, not a divergence with no path back. Same detection, different severity
    /// and a different action — and a report that conflates them tells a provider to go and fix
    /// something that is working as they configured it.
    pub needs_approval: Vec<String>,
    /// Contracted items past their published withdrawal date.
    pub withdrawn: Vec<(String, u64)>,
    /// Contracted items with a withdrawal date still ahead.
    pub withdrawing: Vec<(String, u64)>,
}

impl Affected {
    /// Whether this contract has anything the provider needs to know about.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.gone.is_empty()
            && self.needs_approval.is_empty()
            && self.withdrawn.is_empty()
            && self.withdrawing.is_empty()
    }
}

/// What the offer now in force means for the contracts already out there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Impact {
    /// The version published.
    pub version: u64,
    /// Live contracts naming this asset.
    pub live: usize,
    /// How many were minted under an earlier version of the offer.
    pub behind: usize,
    /// Every contract with something to report, worst first.
    pub affected: Vec<Affected>,
}

/// One live contract as this analysis needs it: the record, plus the consumer's zone and tier
/// **as they are now**.
///
/// Now rather than at mint time, and the distinction matters: the question being answered is
/// *what would happen on the consumer's next build*, and that is evaluated against the registry
/// as it stands. A consumer whose tier was raised out of an audience is as affected as one whose
/// item was withdrawn, and neither is visible from the contract record alone — `ContractRecord`
/// keeps the caller's zone but not its tier.
#[derive(Debug, Clone, Copy)]
pub struct LiveContract<'a> {
    /// The record.
    pub record: &'a ContractRecord,
    /// The consumer's zone in the registry now.
    pub consumer_zone: &'a str,
    /// The consumer's tier in the registry now.
    pub consumer_tier: Tier,
}

/// One thing a lint found, and how much it matters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// `error` refuses; `warning` is a term that mints and is probably not what was meant.
    pub error: bool,
    /// What is wrong, in words a provider can act on.
    pub detail: String,
}

/// Check an offer for terms that are valid and probably wrong.
///
/// # Why this is separate from `into_offer`
///
/// `into_offer` refuses what cannot work: no terms, an empty item list, a `ttl_max` of zero or past
/// the ceiling, an item outside the declared surface. Those are errors and it is right to refuse
/// them.
///
/// What is left is worse in one way: terms that parse, mint, and do something the provider did not
/// intend. A withdrawal date already in the past silently makes an item unreachable. A withdrawal
/// date closer than the term's own ceiling refuses every contract at that ceiling — the consumer
/// sees "lower your ttl" and the provider never learns their two numbers disagree. Neither is
/// visible until somebody's build breaks.
///
/// # Runs with nothing
///
/// Takes the manifest and the surface, not a control plane. A provider's CI has no state log, no
/// key and no registry — and the moment to catch a bad term is before the merge, in the repository
/// where it was written.
#[must_use]
pub fn lint(manifest: &OfferManifest, declared: &BTreeSet<String>, now: u64) -> Vec<Finding> {
    let mut out = Vec::new();

    // Errors first, mirroring `into_offer` so a lint that passes means a publish will too. Repeating
    // the checks rather than calling it: `into_offer` stops at the first problem, and a provider
    // fixing terms wants all of them at once.
    if manifest.terms.is_empty() {
        out.push(Finding {
            error: true,
            detail: "no terms: an offer with no terms permits nothing and is not a catalogue entry"
                .to_string(),
        });
    }
    for (i, term) in manifest.terms.iter().enumerate() {
        if term.items.is_empty() {
            out.push(Finding {
                error: true,
                detail: format!("term {i}: no items"),
            });
        }
        if term.ttl_max == 0 {
            out.push(Finding {
                error: true,
                detail: format!("term {i}: ttl_max is 0, so nothing can be contracted under it"),
            });
        }
        for item in &term.items {
            if !declared.contains(item) {
                out.push(Finding {
                    error: true,
                    detail: format!(
                        "term {i}: {item:?} is not in the declared surface, so the term grants \
                         something this server does not expose"
                    ),
                });
            }
        }

        // --- the warnings: valid, and probably not meant ---
        if term.to.zone.is_none() && term.to.tier.is_none() {
            out.push(Finding {
                error: false,
                detail: format!(
                    "term {i}: no audience, so every registered consumer may ask. Legitimate for a \
                     read-only tool and rarely meant for anything else — set `to = {{ zone = … }}`"
                ),
            });
        }
        for dep in &term.deprecates {
            if !term.items.iter().any(|it| it == &dep.item) {
                out.push(Finding {
                    error: false,
                    detail: format!(
                        "term {i}: deprecates {:?}, which this term does not offer — the schedule \
                         binds nothing",
                        dep.item
                    ),
                });
            }
            if dep.after <= now {
                out.push(Finding {
                    error: false,
                    detail: format!(
                        "term {i}: {:?} was withdrawn on {} — it is already unreachable, and a \
                         consumer asking for it is refused rather than told it is going",
                        dep.item,
                        crate::export::iso8601(dep.after)
                    ),
                });
            } else if dep.after.saturating_sub(now) < term.ttl_max {
                // The trap worth catching. `match_need` refuses a contract that would outlive a
                // withdrawal date, so a ceiling longer than the remaining window means every
                // consumer at that ceiling is refused — and the message they see says "lower your
                // ttl", which never reaches the provider whose two numbers disagree.
                out.push(Finding {
                    error: false,
                    detail: format!(
                        "term {i}: {:?} is withdrawn on {} — {}s away — but ttl_max is {}s, so \
                         every consumer asking for the full ceiling is refused. Lower ttl_max or \
                         move the date",
                        dep.item,
                        crate::export::iso8601(dep.after),
                        dep.after.saturating_sub(now),
                        term.ttl_max
                    ),
                });
            }
        }
    }

    // An item in two terms: the strictest wins, so the other is dead weight. Reported because a
    // provider editing the lenient one will see no change and conclude the file is not being read.
    let mut seen: std::collections::BTreeMap<&str, Vec<usize>> = std::collections::BTreeMap::new();
    for (i, term) in manifest.terms.iter().enumerate() {
        for item in &term.items {
            seen.entry(item.as_str()).or_default().push(i);
        }
    }
    for (item, terms) in seen {
        if terms.len() > 1 {
            out.push(Finding {
                error: false,
                detail: format!(
                    "{item:?} appears in terms {terms:?}. The strictest applies and the others are \
                     inert — editing one of those will look like the file is being ignored"
                ),
            });
        }
    }
    out
}

/// Judge live contracts against the offer now in force.
///
/// **A version bump changes nothing about a contract already issued**, and that is deliberate:
/// a contract is a signed ceiling with a hard expiry, and letting a publisher shorten one
/// remotely would make the artifact a cache of a mutable decision rather than a decision. So
/// this reports rather than acts, and the three things that actually close the gap are the
/// contract's own `exp`, the consumer's next build (where `match_need` refuses what the offer no
/// longer permits), and the surface pin — a provider who truly removes a tool causes `WC-3108`
/// drift at the mediator, which fails closed without anyone publishing anything.
#[must_use]
pub fn impact(offer: &Offer, live: &[LiveContract<'_>], now: u64) -> Impact {
    let mut affected = Vec::new();
    let mut behind = 0;

    for c in live {
        if c.record.offer_version.is_some_and(|v| v < offer.version) {
            behind += 1;
        }
        let mut row = Affected {
            cid: c.record.cid.as_str().to_string(),
            consumer: c.record.caller.clone(),
            minted_under: c.record.offer_version,
            exp: c.record.exp,
            gone: Vec::new(),
            needs_approval: Vec::new(),
            withdrawn: Vec::new(),
            withdrawing: Vec::new(),
        };
        for item in c.record.surface.items() {
            match offer.permits(&item, c.consumer_zone, c.consumer_tier) {
                TermOutcome::NotOffered { .. } => row.gone.push(item),
                TermOutcome::NeedsNamedApproval { .. } => row.needs_approval.push(item),
                TermOutcome::PreGranted { .. } => match offer.deprecated_after(&item) {
                    Some(after) if now >= after => row.withdrawn.push((item, after)),
                    Some(after) => row.withdrawing.push((item, after)),
                    None => {}
                },
            }
        }
        if !row.is_clean() {
            affected.push(row);
        }
    }

    // Worst first: contracts holding something already gone, then something past its date, then
    // something scheduled. An operator reading a long list needs the top of it to be the part
    // that cannot wait.
    // Worst first, and `needs_approval` sits deliberately between `withdrawn` and `withdrawing`:
    // it blocks the consumer's next build, which a future withdrawal date does not, but there is a
    // person who can unblock it, which a passed date has not.
    affected.sort_by(|a, b| {
        (
            b.gone.len(),
            b.withdrawn.len(),
            b.needs_approval.len(),
            b.withdrawing.len(),
        )
            .cmp(&(
                a.gone.len(),
                a.withdrawn.len(),
                a.needs_approval.len(),
                a.withdrawing.len(),
            ))
            .then_with(|| a.cid.cmp(&b.cid))
    });

    Impact {
        version: offer.version,
        live: live.len(),
        behind,
        affected,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    const SURFACE_DIGEST: &str = "sha256:ffff";

    fn tier(n: u8) -> Tier {
        Tier::new(n).unwrap()
    }

    fn declared() -> BTreeSet<String> {
        ["get_balance", "list_transactions", "transfer_funds"]
            .into_iter()
            .map(String::from)
            .collect()
    }

    fn source() -> OfferSource {
        OfferSource {
            repo: "bank/payments-mcp".to_string(),
            sha: "05e9bde".to_string(),
            manifest_digest: "sha256:aaaa".to_string(),
        }
    }

    fn offer_from(toml_text: &str) -> Result<Offer> {
        OfferManifest::parse(toml_text)?.into_offer(
            &declared(),
            SurfaceKind::McpTools,
            SURFACE_DIGEST,
            7,
            source(),
        )
    }

    const TWO_TERMS: &str = r#"
asset = "spiffe://bank/ns/svc/sa/payments-mcp"

[[term]]
items = ["get_balance", "list_transactions"]
approval = "pre_granted"
ttl_max = 2592000
to = { zone = "internal.*", tier = { op = "lt", value = 3 } }

[[term]]
items = ["transfer_funds"]
approval = "named_consumer"
ttl_max = 86400
"#;

    #[test]
    fn a_pre_granted_item_is_contractable_by_a_consumer_in_the_audience() {
        let offer = offer_from(TWO_TERMS).unwrap();
        assert_eq!(
            offer.permits("get_balance", "internal.apac-ops", tier(2)),
            TermOutcome::PreGranted { ttl_max: 2_592_000 }
        );
    }

    #[test]
    fn a_named_consumer_item_is_gated_rather_than_treated_as_pre_granted() {
        // The most sensitive term must never collapse into the most permissive one. It used to be
        // refused outright, which was honest while nothing could route an approval; now it carries
        // the term's own ceiling into a request. What must not change is that it is *not*
        // pre-granted, and that the ceiling is the guarded term's rather than the lenient one's.
        let offer = offer_from(TWO_TERMS).unwrap();
        assert_eq!(
            offer.permits("transfer_funds", "internal.apac-ops", tier(2)),
            TermOutcome::NeedsNamedApproval { ttl_max: 86_400 }
        );
    }

    #[test]
    fn an_out_of_audience_consumer_is_told_the_item_exists() {
        // "That item is not offered" and "it is not offered to you" are different
        // conversations with the provider, so the outcome distinguishes them.
        let offer = offer_from(TWO_TERMS).unwrap();
        assert_eq!(
            offer.permits("get_balance", "partner.acme", tier(2)),
            TermOutcome::NotOffered { item_exists: true }
        );
        assert_eq!(
            offer.permits("nonexistent", "internal.apac-ops", tier(2)),
            TermOutcome::NotOffered { item_exists: false }
        );
    }

    #[test]
    fn a_tier_outside_the_term_is_not_admitted() {
        let offer = offer_from(TWO_TERMS).unwrap();
        // `lt 3` means tiers 1 and 2. Tier 3 is outside it.
        assert_eq!(
            offer.permits("get_balance", "internal.apac-ops", tier(3)),
            TermOutcome::NotOffered { item_exists: true }
        );
    }

    #[test]
    fn the_strictest_term_wins_regardless_of_the_order_it_was_written_in() {
        // The defect this prevents is `cpolicy`'s: a money-movement rule sat below a generic
        // tier rule, so its cap never applied. Here the same item is covered twice, and both
        // orderings must give the strict answer — so moving a term in a file cannot change a
        // decision.
        let lenient_first = r#"
asset = "spiffe://bank/ns/svc/sa/payments-mcp"
[[term]]
items = ["transfer_funds"]
approval = "pre_granted"
ttl_max = 3600
[[term]]
items = ["transfer_funds"]
approval = "named_consumer"
ttl_max = 3600
"#;
        let strict_first = r#"
asset = "spiffe://bank/ns/svc/sa/payments-mcp"
[[term]]
items = ["transfer_funds"]
approval = "named_consumer"
ttl_max = 3600
[[term]]
items = ["transfer_funds"]
approval = "pre_granted"
ttl_max = 3600
"#;
        for text in [lenient_first, strict_first] {
            assert_eq!(
                offer_from(text)
                    .unwrap()
                    .permits("transfer_funds", "internal.x", tier(1)),
                TermOutcome::NeedsNamedApproval { ttl_max: 3600 },
                "term order must not decide the outcome"
            );
        }
    }

    #[test]
    fn a_term_naming_an_item_the_surface_does_not_declare_is_refused() {
        let text = r#"
asset = "spiffe://bank/ns/svc/sa/payments-mcp"
[[term]]
items = ["get_balance", "drop_database"]
approval = "pre_granted"
ttl_max = 3600
"#;
        let err = offer_from(text).unwrap_err();
        assert_eq!(err.code(), Code::SURFACE_NOT_SUBSET);
        assert!(err.detail().contains("drop_database"), "{}", err.detail());
    }

    #[test]
    fn an_unbounded_ttl_is_refused_because_expiry_is_the_last_containment_bound() {
        let text = r#"
asset = "spiffe://bank/ns/svc/sa/payments-mcp"
[[term]]
items = ["get_balance"]
approval = "pre_granted"
ttl_max = 315360000
"#;
        assert_eq!(offer_from(text).unwrap_err().code(), Code::POLICY_INVALID);
    }

    #[test]
    fn an_empty_offer_is_refused_so_not_onboarded_stays_distinguishable() {
        let text = "asset = \"spiffe://bank/ns/svc/sa/payments-mcp\"\n";
        assert_eq!(offer_from(text).unwrap_err().code(), Code::POLICY_INVALID);
    }

    #[test]
    fn deprecating_an_item_the_term_does_not_offer_is_refused() {
        let text = r#"
asset = "spiffe://bank/ns/svc/sa/payments-mcp"
[[term]]
items = ["get_balance"]
approval = "pre_granted"
ttl_max = 3600
deprecates = [{ item = "list_transactions", after = 1800000000 }]
"#;
        assert_eq!(offer_from(text).unwrap_err().code(), Code::POLICY_INVALID);
    }

    #[test]
    fn the_earliest_deprecation_date_is_the_one_a_consumer_must_plan_around() {
        let text = r#"
asset = "spiffe://bank/ns/svc/sa/payments-mcp"
[[term]]
items = ["get_balance"]
approval = "pre_granted"
ttl_max = 3600
deprecates = [{ item = "get_balance", after = 2000 }]
[[term]]
items = ["get_balance"]
approval = "pre_granted"
ttl_max = 3600
deprecates = [{ item = "get_balance", after = 1000 }]
"#;
        assert_eq!(
            offer_from(text).unwrap().deprecated_after("get_balance"),
            Some(1000)
        );
        assert_eq!(
            offer_from(TWO_TERMS)
                .unwrap()
                .deprecated_after("get_balance"),
            None
        );
    }

    // --- the upgrade question ------------------------------------------------

    const NOW: u64 = 1_785_312_500;

    fn record(cid: &str, consumer: &str, tools: &[&str], version: Option<u64>) -> ContractRecord {
        use wc_core::contract::{ApprovalRef, ContractStatus, Surface, Terms};
        use wc_core::model::{Cid, Jti, ZoneId};
        ContractRecord {
            cid: Cid::new(cid).unwrap(),
            jti: Jti::new("cx_000000000000000000000001").unwrap(),
            caller: EntityId::new(consumer).unwrap(),
            callee: EntityId::new("spiffe://bank/ns/svc/sa/payments-mcp").unwrap(),
            caller_zone: ZoneId::new("internal.apac").unwrap(),
            callee_zone: ZoneId::new("internal.payments").unwrap(),
            callee_tier: tier(2),
            callee_manifest: "sha256:m".to_string(),
            surface_digest: "sha256:d".to_string(),
            surface: Surface {
                tools: tools.iter().map(|t| (*t).to_string()).collect(),
                ..Surface::default()
            },
            terms: Terms::default(),
            aud: vec!["warden:mediator:apac".to_string()],
            jws_sha256: "sha256:j".to_string(),
            status: ContractStatus::Active,
            approval: ApprovalRef::standing(),
            policy_version: "connect-policy@v1".to_string(),
            iat: NOW - 100,
            exp: NOW + 86_400,
            offer_version: version,
            schema: wc_core::contract::CONTRACT_SCHEMA,
        }
    }

    fn declared_set(items: &[&str]) -> std::collections::BTreeSet<String> {
        items.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn lint_is_clean_on_an_offer_that_says_what_it_means() {
        let m = OfferManifest::parse(
            r#"
asset = "spiffe://bank/ns/svc/sa/pay"

[[term]]
items = ["get_balance"]
approval = "pre_granted"
ttl_max = 3600
to = { zone = "internal.*" }
"#,
        )
        .unwrap();
        assert!(
            lint(&m, &declared_set(&["get_balance"]), NOW).is_empty(),
            "a clean offer must produce nothing, or the noise trains people to ignore it"
        );
    }

    #[test]
    fn lint_catches_a_withdrawal_closer_than_the_ceiling_it_sits_beside() {
        // The trap worth having a lint for. `match_need` refuses a contract that would outlive a
        // withdrawal date, so a ceiling longer than the remaining window refuses every consumer
        // asking for the full ceiling — and the message THEY see says "lower your ttl", which
        // never reaches the provider whose two numbers disagree.
        let m = OfferManifest::parse(&format!(
            r#"
asset = "spiffe://bank/ns/svc/sa/pay"

[[term]]
items = ["get_balance"]
approval = "pre_granted"
ttl_max = 604800
to = {{ zone = "internal.*" }}
deprecates = [{{ item = "get_balance", after = {} }}]
"#,
            NOW + 86_400
        ))
        .unwrap();
        let found = lint(&m, &declared_set(&["get_balance"]), NOW);
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(!found[0].error, "this mints, so it is a warning");
        assert!(
            found[0].detail.contains("Lower ttl_max or move the date"),
            "the finding must say what to do: {}",
            found[0].detail
        );
    }

    #[test]
    fn lint_catches_a_date_already_passed_and_an_item_in_two_terms() {
        let m = OfferManifest::parse(&format!(
            r#"
asset = "spiffe://bank/ns/svc/sa/pay"

[[term]]
items = ["get_balance", "transfer_funds"]
approval = "pre_granted"
ttl_max = 3600
to = {{ zone = "internal.*" }}
deprecates = [{{ item = "get_balance", after = {} }}]

[[term]]
items = ["transfer_funds"]
approval = "named_consumer"
ttl_max = 3600
"#,
            NOW - 100
        ))
        .unwrap();
        let found = lint(&m, &declared_set(&["get_balance", "transfer_funds"]), NOW);
        let all: String = found.iter().map(|f| f.detail.clone()).collect();
        assert!(all.contains("already unreachable"), "{all}");
        // The shadowed term. A provider editing the inert one sees no change and concludes the
        // file is not being read.
        assert!(all.contains("appears in terms [0, 1]"), "{all}");
        // No audience at all on term 1.
        assert!(all.contains("no audience"), "{all}");
        assert!(
            found.iter().all(|f| !f.error),
            "none of these blocks a publish"
        );
    }

    #[test]
    fn lint_reports_every_error_rather_than_stopping_at_the_first() {
        // `into_offer` stops at the first problem, which is right for a refusal and wrong for a
        // provider fixing terms — they want the whole list in one run.
        let m = OfferManifest::parse(
            r#"
asset = "spiffe://bank/ns/svc/sa/pay"

[[term]]
items = ["nope_one", "nope_two"]
approval = "pre_granted"
ttl_max = 3600
to = { zone = "internal.*" }

[[term]]
items = ["nope_three"]
approval = "pre_granted"
ttl_max = 3600
to = { zone = "internal.*" }
"#,
        )
        .unwrap();
        let found = lint(&m, &declared_set(&["get_balance"]), NOW);
        let errors: Vec<&Finding> = found.iter().filter(|f| f.error).collect();
        // Two bad items in ONE term plus one in another, deliberately. An earlier version used one
        // item per term, so a mutation reporting only the first item of each still produced the
        // expected count — the test proved the loop over terms and said nothing about the loop over
        // items inside them.
        assert_eq!(
            errors.len(),
            3,
            "every undeclared item must be named, across terms and within one: {found:?}"
        );
        let all: String = errors.iter().map(|f| f.detail.clone()).collect();
        for bad in ["nope_one", "nope_two", "nope_three"] {
            assert!(all.contains(bad), "{bad} was not reported: {all}");
        }
    }

    #[test]
    fn lint_catches_a_deprecation_for_an_item_the_term_does_not_offer() {
        // A schedule that binds nothing. The provider believes they announced a withdrawal.
        let m = OfferManifest::parse(&format!(
            r#"
asset = "spiffe://bank/ns/svc/sa/pay"

[[term]]
items = ["get_balance"]
approval = "pre_granted"
ttl_max = 3600
to = {{ zone = "internal.*" }}
deprecates = [{{ item = "transfer_funds", after = {} }}]
"#,
            NOW + 999_999
        ))
        .unwrap();
        let found = lint(&m, &declared_set(&["get_balance", "transfer_funds"]), NOW);
        assert!(
            found.iter().any(|f| f.detail.contains("binds nothing")),
            "{found:?}"
        );
    }

    #[test]
    fn the_catalogue_shows_a_consumer_only_what_they_may_ask_for() {
        let offer = offer_from(TWO_TERMS).unwrap();
        let seen = offer
            .as_seen_by("internal.apac-ops", tier(2), NOW)
            .expect("in the audience of the pre-granted term");
        // Split by what the consumer can do next, which is the only distinction that changes their
        // behaviour: contract it, or ask for it.
        assert_eq!(
            seen.pre_granted,
            vec!["get_balance".to_string(), "list_transactions".to_string()]
        );
        assert_eq!(seen.needs_approval, vec!["transfer_funds".to_string()]);
    }

    #[test]
    fn a_consumer_outside_every_audience_is_told_nothing_at_all() {
        // The property that makes a browsable catalogue safe. `TWO_TERMS`'s pre-granted term admits
        // `internal.*` below tier 3; the named-consumer term has no audience clause, so it admits
        // anyone — which is why this test uses a fixture where every term is scoped.
        let scoped = offer_from(
            r#"
asset = "spiffe://bank/ns/svc/sa/payments-mcp"

[[term]]
items = ["get_balance"]
approval = "pre_granted"
ttl_max = 3600
to = { zone = "internal.payments-only" }

[[term]]
items = ["transfer_funds"]
approval = "named_consumer"
ttl_max = 3600
to = { zone = "internal.payments-only" }
"#,
        )
        .unwrap();
        assert!(
            scoped.as_seen_by("partner.acme", tier(1), NOW).is_none(),
            "an out-of-audience consumer must not learn the asset exists, and an entry with empty \
             lists would tell them exactly that"
        );
        assert!(scoped
            .as_seen_by("internal.payments-only", tier(1), NOW)
            .is_some());
    }

    #[test]
    fn the_catalogue_does_not_advertise_an_item_already_withdrawn() {
        // A date in the past means the item is gone; `match_need` refuses it. Listing it would
        // invite a request that cannot succeed, which is worse than not listing it.
        let mut offer = offer_from(TWO_TERMS).unwrap();
        offer.terms[0].deprecates = vec![Deprecation {
            item: "get_balance".to_string(),
            after: NOW - 1,
        }];
        let seen = offer.as_seen_by("internal.apac-ops", tier(2), NOW).unwrap();
        assert!(
            !seen.withdrawing.iter().any(|(i, _)| i == "get_balance"),
            "a passed date is not a schedule: {:?}",
            seen.withdrawing
        );
    }

    #[test]
    fn impact_finds_the_contracts_a_removal_would_break() {
        let mut offer = offer_from(TWO_TERMS).unwrap();
        offer.version = 9;
        offer.terms[0].deprecates = vec![Deprecation {
            item: "list_transactions".to_string(),
            after: NOW + 30 * 86_400,
        }];

        // Three consumers: one clean, one holding an item that needs named approval under the
        // current terms, one holding a scheduled item under an older offer version.
        let clean = record(
            "conn_1111111111111111",
            "spiffe://bank/ns/a/sa/one",
            &["get_balance"],
            Some(9),
        );
        let broken = record(
            "conn_2222222222222222",
            "spiffe://bank/ns/a/sa/two",
            &["transfer_funds"],
            Some(9),
        );
        let stale = record(
            "conn_3333333333333333",
            "spiffe://bank/ns/a/sa/three",
            &["get_balance", "list_transactions"],
            Some(4),
        );
        let live: Vec<LiveContract<'_>> = [&clean, &broken, &stale]
            .into_iter()
            .map(|r| LiveContract {
                record: r,
                consumer_zone: "internal.apac",
                consumer_tier: tier(2),
            })
            .collect();

        let i = impact(&offer, &live, NOW);
        assert_eq!(i.version, 9);
        assert_eq!(i.live, 3);
        assert_eq!(i.behind, 1, "only the version-4 contract is behind");

        // The clean one is absent, not present-and-empty: a report an operator has to filter is
        // a report they stop reading.
        assert_eq!(i.affected.len(), 2);

        // Worst first. `transfer_funds` needs named approval under the current terms — reported
        // apart from `gone`, because the consumer *can* get it today by asking the provider. While
        // named approval routed nowhere these were the same row; conflating them now would tell a
        // provider to fix a term that is behaving exactly as they configured it.
        assert_eq!(i.affected[0].cid, "conn_2222222222222222");
        assert!(i.affected[0].gone.is_empty(), "not gone — gated");
        assert_eq!(
            i.affected[0].needs_approval,
            vec!["transfer_funds".to_string()]
        );
        assert_eq!(i.affected[0].minted_under, Some(9));

        assert_eq!(i.affected[1].cid, "conn_3333333333333333");
        assert!(i.affected[1].gone.is_empty());
        assert_eq!(
            i.affected[1].withdrawing,
            vec![("list_transactions".to_string(), NOW + 30 * 86_400)]
        );
    }

    #[test]
    fn impact_separates_a_passed_withdrawal_from_a_scheduled_one() {
        let mut offer = offer_from(TWO_TERMS).unwrap();
        offer.terms[0].deprecates = vec![Deprecation {
            item: "get_balance".to_string(),
            after: NOW - 1,
        }];
        let r = record(
            "conn_4444444444444444",
            "spiffe://bank/ns/a/sa/four",
            &["get_balance"],
            Some(7),
        );
        let live = [LiveContract {
            record: &r,
            consumer_zone: "internal.apac",
            consumer_tier: tier(2),
        }];

        let i = impact(&offer, &live, NOW);
        assert_eq!(i.affected.len(), 1);
        assert_eq!(
            i.affected[0].withdrawn,
            vec![("get_balance".to_string(), NOW - 1)]
        );
        assert!(i.affected[0].withdrawing.is_empty());
    }

    #[test]
    fn a_contract_from_a_direct_request_is_not_counted_as_behind() {
        // `None` is not "version zero". A human who requested a contract directly was never on
        // the offer's version track, and counting them as behind would make every estate look
        // permanently out of date — an alarm that is always on is not read.
        let offer = offer_from(TWO_TERMS).unwrap();
        let r = record(
            "conn_5555555555555555",
            "spiffe://bank/ns/a/sa/five",
            &["get_balance"],
            None,
        );
        let live = [LiveContract {
            record: &r,
            consumer_zone: "internal.apac",
            consumer_tier: tier(2),
        }];

        let i = impact(&offer, &live, NOW);
        assert_eq!(i.behind, 0);
        assert!(i.affected.is_empty());
    }

    #[test]
    fn impact_judges_the_audience_as_it_stands_now_not_at_mint_time() {
        // The consumer's tier was raised out of the audience after the contract was minted. The
        // contract is still live and still authorises the item — and the consumer's next build
        // will refuse, so the provider needs to see it. `ContractRecord` keeps the caller's zone
        // but not its tier, so this can only be answered from the registry.
        let offer = offer_from(TWO_TERMS).unwrap();
        let r = record(
            "conn_6666666666666666",
            "spiffe://bank/ns/a/sa/six",
            &["get_balance"],
            Some(7),
        );
        let inside = [LiveContract {
            record: &r,
            consumer_zone: "internal.apac",
            consumer_tier: tier(2),
        }];
        assert!(impact(&offer, &inside, NOW).affected.is_empty());

        // tier 3 fails `tier = { op = "lt", value = 3 }`.
        let outside = [LiveContract {
            record: &r,
            consumer_zone: "internal.apac",
            consumer_tier: tier(3),
        }];
        let i = impact(&offer, &outside, NOW);
        assert_eq!(i.affected.len(), 1);
        assert_eq!(i.affected[0].gone, vec!["get_balance".to_string()]);
    }

    #[test]
    fn an_offer_round_trips_through_serde_because_it_is_persisted() {
        let offer = offer_from(TWO_TERMS).unwrap();
        let wire = serde_json::to_string(&offer).unwrap();
        let back: Offer = serde_json::from_str(&wire).unwrap();
        assert_eq!(back.version, 7);
        assert_eq!(back.surface_digest, SURFACE_DIGEST);
        assert_eq!(back.source.repo, "bank/payments-mcp");
        assert_eq!(
            back.permits("get_balance", "internal.x", tier(1)),
            TermOutcome::PreGranted { ttl_max: 2_592_000 }
        );
    }

    #[test]
    fn an_absent_audience_admits_anyone_rather_than_silently_narrowing() {
        let offer = offer_from(TWO_TERMS).unwrap();
        // The second term has no `to`, so it is open — which is a real thing to publish.
        assert!(Audience::default().admits("anything.at.all", tier(4)));
        assert!(offer.offered_items().contains("transfer_funds"));
    }

    // --- the surface attestation ------------------------------------------------

    fn card_key() -> IssuerKey {
        // The card-signing key from the independently-minted fixtures, so this test signs with
        // material `cryptography` produced rather than something our own Rust invented.
        let pem = std::fs::read("../../fixtures/attest/card-signer.priv.pem")
            .expect("fixtures/attest is regenerated by scripts/gen-attest-fixtures.py");
        IssuerKey::ec_pem("card-signer-1", &pem, wc_core::contract::Algorithm::ES256).unwrap()
    }

    /// An admission request carrying a surface document as the card.
    fn req_with(card: &Value) -> crate::admission::AdmissionRequest {
        crate::admission::AdmissionRequest {
            kind: wc_core::model::Kind::McpServer,
            id: Some(EntityId::new("spiffe://bank/ns/svc/sa/payments-mcp").unwrap()),
            card: Some(card.clone()),
            endpoint: None,
            attestation: Vec::new(),
            owner: wc_core::model::HumanRef::new("human:priya@org").unwrap(),
            zone: wc_core::model::ZoneId::new("internal.payments").unwrap(),
            declared: Default::default(),
            mode: wc_core::error::Mode::Enforce,
        }
    }

    fn fetched_of(doc: &Value) -> crate::admission::FetchedSurface {
        crate::admission::FetchedSurface {
            kind: SurfaceKind::McpTools,
            raw: doc.clone(),
            source: "test".to_string(),
        }
    }

    #[test]
    fn an_unsigned_surface_is_unverified_which_is_what_made_enforce_mode_unreachable() {
        // The blocker, pinned. `Posture::Attested` needs `card.verified`, and this is the
        // document every real MCP server produces: a tools/list result with no `signatures`.
        // Unverified here means Unattested, and WC-3109 is ClosedUnlessObserve — so enforce
        // mode refused every call. If this assertion ever flips, the bar was lowered.
        use crate::admission::CardVerifier;
        use crate::attest::JwksCardVerifier;
        let surface = serde_json::json!({
            "tools": [{"name": "get_balance", "description": "Read a balance."}]
        });
        let keys = wc_core::contract::IssuerKeys::new();
        let v = JwksCardVerifier {
            keys: &keys,
            require_signature: false,
        };
        let proof = v
            .verify_card(&req_with(&surface), &fetched_of(&surface))
            .expect("an unsigned card is a skip, not an error, when signatures are optional");
        assert!(
            !proof.verified,
            "an unsigned surface must not count as attested — the pin would vouch for nothing"
        );
    }

    #[test]
    fn an_attested_surface_verifies_through_the_verifier_that_used_to_reject_it() {
        // The fix, proven against the real verifier rather than against my own reading of it.
        // Nothing in `attest.rs` changed: the gap was that nobody produced the input it wanted.
        use crate::admission::CardVerifier;
        use crate::attest::{card_signing_input, JwksCardVerifier, CARD_SIGNATURES_FIELD};
        use wc_core::contract::{Algorithm, IssuerKeys};

        let surface = serde_json::json!({
            "tools": [{"name": "get_balance", "description": "Read a balance."}]
        });
        let signed = attest_surface(&surface, &card_key()).unwrap();

        // Adding the signature must not change what the signature covers, or it would be
        // signing over itself and could never be checked.
        assert_eq!(card_signing_input(&signed), card_signing_input(&surface));
        assert_eq!(signed[CARD_SIGNATURES_FIELD].as_array().unwrap().len(), 1);

        let mut keys = IssuerKeys::new();
        let pub_pem = std::fs::read("../../fixtures/attest/card-signer.pub.pem").unwrap();
        keys.add_ec_pem("card-signer-1", &pub_pem, Algorithm::ES256)
            .unwrap();
        let v = JwksCardVerifier {
            keys: &keys,
            require_signature: true,
        };
        let proof = v
            .verify_card(&req_with(&signed), &fetched_of(&signed))
            .expect("the attested surface must verify");
        assert!(
            proof.verified,
            "stage 3 must pass, or Attested stays unreachable and enforce mode stays unusable"
        );
    }

    #[test]
    fn re_attesting_an_already_signed_surface_keeps_both_signatures_verifying() {
        // Found by mutation testing: signing `document.to_string()` instead of the canonical
        // form with `signatures` stripped passed every other test in this module, because for a
        // document with no signatures the two are identical. It only diverges when the document
        // already carries one — which is exactly the re-attestation flow, where a provider signs
        // its own surface and the plane counter-signs.
        use crate::admission::CardVerifier;
        use crate::attest::{JwksCardVerifier, CARD_SIGNATURES_FIELD};
        use wc_core::contract::{Algorithm, IssuerKeys};

        let surface = serde_json::json!({"tools": [{"name": "get_balance"}]});
        let once = attest_surface(&surface, &card_key()).unwrap();
        let twice = attest_surface(&once, &card_key()).unwrap();

        assert_eq!(
            twice[CARD_SIGNATURES_FIELD].as_array().unwrap().len(),
            2,
            "a second attestation must append rather than discard the first"
        );

        let mut keys = IssuerKeys::new();
        let pub_pem = std::fs::read("../../fixtures/attest/card-signer.pub.pem").unwrap();
        keys.add_ec_pem("card-signer-1", &pub_pem, Algorithm::ES256)
            .unwrap();
        let v = JwksCardVerifier {
            keys: &keys,
            require_signature: true,
        };

        // The SECOND signature, alone. `verify_card` treats one trusted signature as the whole
        // claim, so leaving the first in place would let it carry the assertion — and it did:
        // the mutation survived a version of this test that verified `twice` intact. Only the
        // signature made *over a document that already had signatures* proves the signed bytes
        // excluded them.
        let mut second_only = twice.clone();
        let sigs = second_only[CARD_SIGNATURES_FIELD]
            .as_array()
            .unwrap()
            .clone();
        second_only[CARD_SIGNATURES_FIELD] = serde_json::json!([sigs[1]]);

        assert!(
            v.verify_card(&req_with(&second_only), &fetched_of(&second_only))
                .expect("the second signature alone must verify")
                .verified,
            "signing over the canonical document with `signatures` removed is what makes \
             re-attestation possible; signing the raw document would break here"
        );
    }

    #[test]
    fn a_surface_attested_by_an_untrusted_key_does_not_verify() {
        // The signature is not the claim; a signature *from a trusted key* is. Without this
        // the previous test would pass for a document signed by anyone at all.
        use crate::admission::CardVerifier;
        use crate::attest::JwksCardVerifier;
        use wc_core::contract::{Algorithm, IssuerKeys};

        let surface = serde_json::json!({"tools": []});
        let signed = attest_surface(&surface, &card_key()).unwrap();

        let mut keys = IssuerKeys::new();
        // A different key, registered under the same kid the signature names.
        let other = std::fs::read("../../fixtures/attest/builder.pub.pem").unwrap();
        keys.add_ec_pem("card-signer-1", &other, Algorithm::ES256)
            .unwrap();
        let v = JwksCardVerifier {
            keys: &keys,
            require_signature: true,
        };
        assert!(
            v.verify_card(&req_with(&signed), &fetched_of(&signed))
                .is_err(),
            "a signature under an untrusted key must not attest anything"
        );
    }

    #[test]
    fn attesting_a_non_object_is_refused_rather_than_silently_dropped() {
        let err = attest_surface(&serde_json::json!(["tools"]), &card_key()).unwrap_err();
        assert_eq!(err.code(), Code::CONFIG_INVALID);
    }
}
