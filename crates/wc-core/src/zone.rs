//! The zone lattice: structure, ordering, and zone-pair resolution
//! (`docs/08-lld.md` §8.5, HLD §7.4).
//!
//! A zone id is a dotted path over three trust levels — `internal.apac.payments`,
//! `partner.acme`, `public`. Two orderings run through it, and keeping them apart
//! is what makes the model usable:
//!
//! * **Containment**, along the dots. `internal` contains `internal.apac`, which
//!   contains `internal.apac.payments`. This is a forest, one tree per trust level.
//! * **Outwardness**, across trust levels. `Internal < Partner < Public`. A
//!   connection that moves outward is egress; one that moves inward is ingress;
//!   one that stays put is lateral.
//!
//! # Why containment has to be inherited
//!
//! The bar a zone sets is the **strictest** of its own declaration and every
//! ancestor's. Without that, declaring `internal` with a 1-day TTL ceiling and
//! `internal.payments` with 30 days lets the child *widen* the parent — and it
//! reads, in the policy file, as tightening. Most-specific-wins is the right rule
//! for *finding* a declaration and the wrong rule for *applying* one, and this
//! module exists largely to keep those separate.
//!
//! # Why the crossing is named
//!
//! `internal → partner` and `partner → internal` are both "a crossing", and they
//! are not the same risk: the first is data leaving, the second is a counterparty
//! reaching in. A rule that cannot tell them apart cannot express egress control,
//! so [`Crossing`] names all seven cases and [`ZoneLattice`] reports which one it
//! refused.

use std::collections::{BTreeMap, BTreeSet};

use crate::contract::ZoneRule;
use crate::error::{Code, Result, WcError};
use crate::model::{TrustLevel, ZoneId};

// ---------------------------------------------------------------------------
// Ordering
// ---------------------------------------------------------------------------

/// How far from the organisation's own trust boundary a level sits.
///
/// Named rather than derived from the enum's declaration order, so reordering the
/// enum cannot silently invert every egress decision in the system.
#[must_use]
pub const fn outwardness(level: TrustLevel) -> u8 {
    match level {
        TrustLevel::Internal => 0,
        TrustLevel::Partner => 1,
        TrustLevel::Public => 2,
    }
}

/// Every ancestor of a zone, outermost first, including the zone itself.
///
/// `internal.apac.payments` → `[internal, internal.apac, internal.apac.payments]`.
/// Ancestors are what a bar is inherited along.
pub fn ancestors(zone: &ZoneId) -> Vec<ZoneId> {
    let mut out: Vec<ZoneId> = Vec::new();
    let mut path = String::new();
    for segment in zone.as_str().split('.') {
        if !path.is_empty() {
            path.push('.');
        }
        path.push_str(segment);
        // Every prefix of a valid zone id is itself a valid zone id — the first
        // segment is the trust level and the rest are free-form — so this cannot
        // fail for a zone that exists. Skipping rather than unwrapping keeps a
        // future validation change from turning a policy read into a panic.
        if let Ok(id) = ZoneId::new(&path) {
            out.push(id);
        }
    }
    out
}

/// Whether `outer` contains `inner`, reflexively.
#[must_use]
pub fn contains(outer: &ZoneId, inner: &ZoneId) -> bool {
    let (o, i) = (outer.as_str(), inner.as_str());
    i == o || (i.starts_with(o) && i.as_bytes().get(o.len()) == Some(&b'.'))
}

/// The nearest zone containing both, if any.
///
/// `internal.apac.payments` and `internal.apac.ledger` meet at `internal.apac`.
/// Two zones in different trust levels have no common ancestor at all, which is
/// precisely what makes their pairing a crossing.
#[must_use]
pub fn meet(a: &ZoneId, b: &ZoneId) -> Option<ZoneId> {
    let (mut best, av, bv) = (None, ancestors(a), ancestors(b));
    for (x, y) in av.iter().zip(bv.iter()) {
        if x == y {
            best = Some(x.clone());
        } else {
            break;
        }
    }
    best
}

// ---------------------------------------------------------------------------
// Crossings
// ---------------------------------------------------------------------------

/// What kind of boundary a connection crosses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Crossing {
    /// Both ends in the same zone.
    Same,
    /// Caller's zone contains the callee's — moving into a more specific zone.
    Descend,
    /// Callee's zone contains the caller's.
    Ascend,
    /// Same trust level, neither containing the other.
    Lateral,
    /// Internal reaching a partner. Data leaving.
    Egress,
    /// A partner reaching inward. Usually the stricter of the two.
    Ingress,
    /// Either end is public. The most restrictive bar applies.
    Public,
}

impl Crossing {
    /// Whether this crossing stays inside one trust level.
    #[must_use]
    pub const fn is_internal_to_level(self) -> bool {
        matches!(
            self,
            Crossing::Same | Crossing::Descend | Crossing::Ascend | Crossing::Lateral
        )
    }

    /// Label for policy files, reports and denial reasons.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Crossing::Same => "same",
            Crossing::Descend => "descend",
            Crossing::Ascend => "ascend",
            Crossing::Lateral => "lateral",
            Crossing::Egress => "egress",
            Crossing::Ingress => "ingress",
            Crossing::Public => "public",
        }
    }

    /// Parse a crossing name from a policy file.
    pub fn parse(name: &str) -> Result<Crossing> {
        match name {
            "same" => Ok(Crossing::Same),
            "descend" => Ok(Crossing::Descend),
            "ascend" => Ok(Crossing::Ascend),
            "lateral" => Ok(Crossing::Lateral),
            "egress" => Ok(Crossing::Egress),
            "ingress" => Ok(Crossing::Ingress),
            "public" => Ok(Crossing::Public),
            other => Err(WcError::with_detail(
                Code::CONFIG_INVALID,
                format!(
                    "unknown crossing {other:?}; expected one of same, descend, ascend, lateral, egress, ingress, public"
                ),
            )),
        }
    }
}

/// Classify a zone pair.
#[must_use]
pub fn classify(caller: &ZoneId, callee: &ZoneId) -> Crossing {
    let (ct, et) = (caller.trust_level(), callee.trust_level());

    // Public dominates: a public end is the most restrictive case regardless of
    // which direction the call runs, so it is decided before the ordering.
    if ct == TrustLevel::Public || et == TrustLevel::Public {
        return Crossing::Public;
    }
    match outwardness(ct).cmp(&outwardness(et)) {
        std::cmp::Ordering::Less => Crossing::Egress,
        std::cmp::Ordering::Greater => Crossing::Ingress,
        std::cmp::Ordering::Equal => {
            if caller == callee {
                Crossing::Same
            } else if contains(caller, callee) {
                Crossing::Descend
            } else if contains(callee, caller) {
                Crossing::Ascend
            } else {
                Crossing::Lateral
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The lattice
// ---------------------------------------------------------------------------

/// One declared crossing permission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossingRule {
    /// Which crossing this permits.
    pub crossing: Crossing,
    /// Caller zone this applies to, or `None` for any.
    pub from: Option<ZoneId>,
    /// Callee zone this applies to, or `None` for any.
    pub to: Option<ZoneId>,
}

impl CrossingRule {
    /// A rule permitting one crossing kind anywhere.
    #[must_use]
    pub fn any(crossing: Crossing) -> CrossingRule {
        CrossingRule {
            crossing,
            from: None,
            to: None,
        }
    }

    /// A rule permitting one crossing between two zone subtrees.
    #[must_use]
    pub fn between(crossing: Crossing, from: ZoneId, to: ZoneId) -> CrossingRule {
        CrossingRule {
            crossing,
            from: Some(from),
            to: Some(to),
        }
    }

    fn covers(&self, crossing: Crossing, caller: &ZoneId, callee: &ZoneId) -> bool {
        if self.crossing != crossing {
            return false;
        }
        // Zone endpoints match by containment, so a rule written for `partner.acme`
        // also covers `partner.acme.settlement`. A rule for the subtree is the
        // useful unit; requiring one per leaf produces policy files nobody keeps
        // current.
        self.from.as_ref().is_none_or(|z| contains(z, caller))
            && self.to.as_ref().is_none_or(|z| contains(z, callee))
    }
}

/// Why a zone pair was permitted or refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneDecision {
    /// Whether the pair is permitted at the zone layer.
    pub permitted: bool,
    /// What kind of crossing it is.
    pub crossing: Crossing,
    /// The nearest zone containing both ends, if any.
    pub meet: Option<ZoneId>,
    /// A reason an operator can act on.
    pub reason: String,
}

/// The declared zone structure and its crossing rules.
///
/// The default is deny for every crossing that leaves a trust level. Same-level
/// pairs are permitted, because zones inside one trust level exist to organise the
/// estate rather than to separate it — separation is what trust levels are for.
#[derive(Debug, Clone, Default)]
pub struct ZoneLattice {
    declared: BTreeMap<String, TrustLevel>,
    rules: Vec<CrossingRule>,
    /// When set, a zone that is not declared is refused rather than classified
    /// from its first segment.
    strict_membership: bool,
}

impl ZoneLattice {
    /// An empty lattice: same-level pairs permitted, every crossing denied.
    #[must_use]
    pub fn new() -> ZoneLattice {
        ZoneLattice::default()
    }

    /// Declare a zone at a trust level.
    ///
    /// The trust level must match the zone's own first segment. A zone id whose
    /// prefix says `partner` cannot be declared `internal`: the id is what appears
    /// in every contract, log line and register, and letting the two disagree makes
    /// all of them lie.
    pub fn declare(&mut self, zone: &ZoneId, trust: TrustLevel) -> Result<()> {
        if zone.trust_level() != trust {
            return Err(WcError::with_detail(
                Code::CONFIG_INVALID,
                format!(
                    "zone {zone} names trust level {:?} but is declared {trust:?}",
                    zone.trust_level()
                ),
            ));
        }
        self.declared.insert(zone.as_str().to_string(), trust);
        Ok(())
    }

    /// Permit a crossing.
    pub fn permit(&mut self, rule: CrossingRule) {
        self.rules.push(rule);
    }

    /// Refuse any zone that was not declared.
    ///
    /// Off by default, because an estate mid-adoption has zones nobody has
    /// classified yet and refusing them all at once is how a rollout stops. On, it
    /// is the stronger posture: an undeclared zone is an unreviewed zone.
    pub fn set_strict_membership(&mut self, strict: bool) {
        self.strict_membership = strict;
    }

    /// Whether strict membership is on.
    #[must_use]
    pub fn is_strict(&self) -> bool {
        self.strict_membership
    }

    /// How many zones are declared.
    #[must_use]
    pub fn len(&self) -> usize {
        self.declared.len()
    }

    /// Whether nothing is declared.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.declared.is_empty()
    }

    /// Whether this zone, or an ancestor of it, was declared.
    #[must_use]
    pub fn is_declared(&self, zone: &ZoneId) -> bool {
        ancestors(zone)
            .iter()
            .any(|a| self.declared.contains_key(a.as_str()))
    }

    /// Declared zones, outermost first.
    #[must_use]
    pub fn zones(&self) -> Vec<&str> {
        self.declared.keys().map(String::as_str).collect()
    }

    /// Resolve a zone pair, with the reason.
    #[must_use]
    pub fn resolve(&self, caller: &ZoneId, callee: &ZoneId) -> ZoneDecision {
        let crossing = classify(caller, callee);
        let meet = meet(caller, callee);

        if self.strict_membership {
            for (role, zone) in [("caller", caller), ("callee", callee)] {
                if !self.is_declared(zone) {
                    return ZoneDecision {
                        permitted: false,
                        crossing,
                        meet,
                        reason: format!(
                            "{role} zone {zone} is not declared, and strict membership is on"
                        ),
                    };
                }
            }
        }

        if crossing.is_internal_to_level() {
            return ZoneDecision {
                permitted: true,
                crossing,
                meet: meet.clone(),
                reason: format!(
                    "{} within {:?}{}",
                    crossing.as_str(),
                    caller.trust_level(),
                    meet.map_or_else(String::new, |m| format!(", meeting at {m}"))
                ),
            };
        }

        match self
            .rules
            .iter()
            .find(|r| r.covers(crossing, caller, callee))
        {
            Some(rule) => ZoneDecision {
                permitted: true,
                crossing,
                meet,
                reason: format!(
                    "{} permitted by rule {} -> {}",
                    crossing.as_str(),
                    rule.from
                        .as_ref()
                        .map_or_else(|| "*".to_string(), ToString::to_string),
                    rule.to
                        .as_ref()
                        .map_or_else(|| "*".to_string(), ToString::to_string)
                ),
            },
            None => ZoneDecision {
                permitted: false,
                crossing,
                meet,
                reason: format!(
                    "{} from {caller} to {callee} needs an explicit crossing rule",
                    crossing.as_str()
                ),
            },
        }
    }

    /// Static checks over the declarations.
    ///
    /// Reports rather than refuses: a lattice with a questionable declaration
    /// should still load, or one bad line takes the whole estate's policy with it.
    #[must_use]
    pub fn lint(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();

        // A rule whose endpoints contradict its crossing can never fire. That is
        // not a style problem — it is a permission an operator believes they
        // granted and did not.
        for rule in &self.rules {
            if let (Some(from), Some(to)) = (&rule.from, &rule.to) {
                let actual = classify(from, to);
                if actual != rule.crossing {
                    out.push(format!(
                        "rule {} -> {} is declared {} but that pair is {}; it can never match",
                        from,
                        to,
                        rule.crossing.as_str(),
                        actual.as_str()
                    ));
                }
            }
        }

        // Duplicate rules are harmless but usually mean an edit landed twice.
        let mut seen: BTreeSet<(Crossing, Option<String>, Option<String>)> = BTreeSet::new();
        for rule in &self.rules {
            let key = (
                rule.crossing,
                rule.from.as_ref().map(ToString::to_string),
                rule.to.as_ref().map(ToString::to_string),
            );
            if !seen.insert(key) {
                out.push(format!(
                    "duplicate crossing rule for {}",
                    rule.crossing.as_str()
                ));
            }
        }

        // A blanket public rule deserves to be said out loud.
        if self
            .rules
            .iter()
            .any(|r| r.crossing == Crossing::Public && r.from.is_none() && r.to.is_none())
        {
            out.push(
                "a blanket `public` crossing rule permits any party to reach any public zone"
                    .to_string(),
            );
        }
        out
    }
}

impl ZoneRule for ZoneLattice {
    fn permits(&self, caller: &ZoneId, callee: &ZoneId) -> bool {
        self.resolve(caller, callee).permitted
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn z(name: &str) -> ZoneId {
        ZoneId::new(name).unwrap()
    }

    // --- ordering ----------------------------------------------------------

    #[test]
    fn outwardness_is_named_not_derived_from_declaration_order() {
        // Reordering the enum must not silently invert every egress decision.
        assert!(outwardness(TrustLevel::Internal) < outwardness(TrustLevel::Partner));
        assert!(outwardness(TrustLevel::Partner) < outwardness(TrustLevel::Public));
    }

    #[test]
    fn ancestors_run_outermost_first_and_include_the_zone() {
        assert_eq!(
            ancestors(&z("internal.apac.payments"))
                .iter()
                .map(|a| a.as_str().to_string())
                .collect::<Vec<_>>(),
            vec!["internal", "internal.apac", "internal.apac.payments"]
        );
        assert_eq!(
            ancestors(&z("public")).iter().map(|a| a.to_string()).collect::<Vec<_>>(),
            vec!["public"]
        );
    }

    #[test]
    fn containment_is_reflexive_and_respects_segment_boundaries() {
        assert!(contains(&z("internal"), &z("internal.payments")));
        assert!(contains(&z("internal"), &z("internal")));
        assert!(!contains(&z("internal.payments"), &z("internal")));
        // The boundary case a naive prefix check gets wrong.
        assert!(!contains(&z("internal.pay"), &z("internal.payments")));
    }

    #[test]
    fn zones_meet_at_their_nearest_common_ancestor() {
        assert_eq!(
            meet(&z("internal.apac.payments"), &z("internal.apac.ledger")).map(|m| m.to_string()),
            Some("internal.apac".to_string())
        );
        assert_eq!(
            meet(&z("internal.apac"), &z("internal.emea")).map(|m| m.to_string()),
            Some("internal".to_string())
        );
        // Different trust levels share nothing, which is what makes them a crossing.
        assert_eq!(meet(&z("internal.apac"), &z("partner.acme")), None);
    }

    // --- crossings ---------------------------------------------------------

    #[test]
    fn every_crossing_is_classified() {
        assert_eq!(classify(&z("internal.a"), &z("internal.a")), Crossing::Same);
        assert_eq!(
            classify(&z("internal"), &z("internal.payments")),
            Crossing::Descend
        );
        assert_eq!(
            classify(&z("internal.payments"), &z("internal")),
            Crossing::Ascend
        );
        assert_eq!(
            classify(&z("internal.apac"), &z("internal.emea")),
            Crossing::Lateral
        );
        assert_eq!(
            classify(&z("internal.apac"), &z("partner.acme")),
            Crossing::Egress
        );
        assert_eq!(
            classify(&z("partner.acme"), &z("internal.apac")),
            Crossing::Ingress
        );
        assert_eq!(classify(&z("internal.a"), &z("public")), Crossing::Public);
        assert_eq!(classify(&z("public"), &z("internal.a")), Crossing::Public);
        assert_eq!(classify(&z("partner.acme"), &z("public")), Crossing::Public);
    }

    #[test]
    fn egress_and_ingress_are_distinguishable() {
        // A rule that cannot tell "data leaving" from "a counterparty reaching in"
        // cannot express egress control at all.
        let out = classify(&z("internal.apac"), &z("partner.acme"));
        let inward = classify(&z("partner.acme"), &z("internal.apac"));
        assert_ne!(out, inward);
        assert!(!out.is_internal_to_level() && !inward.is_internal_to_level());
    }

    #[test]
    fn crossing_names_round_trip() {
        for c in [
            Crossing::Same,
            Crossing::Descend,
            Crossing::Ascend,
            Crossing::Lateral,
            Crossing::Egress,
            Crossing::Ingress,
            Crossing::Public,
        ] {
            assert_eq!(Crossing::parse(c.as_str()).unwrap(), c);
        }
        let err = Crossing::parse("outbound").unwrap_err();
        assert_eq!(err.code(), Code::CONFIG_INVALID);
        assert!(err.to_string().contains("egress"), "{err}");
    }

    // --- resolution --------------------------------------------------------

    #[test]
    fn same_level_pairs_are_permitted_with_their_meet_named() {
        let l = ZoneLattice::new();
        let d = l.resolve(&z("internal.apac.payments"), &z("internal.apac.ledger"));
        assert!(d.permitted);
        assert_eq!(d.crossing, Crossing::Lateral);
        assert_eq!(d.meet.as_ref().map(|m| m.to_string()), Some("internal.apac".to_string()));
        assert!(d.reason.contains("meeting at internal.apac"), "{}", d.reason);
    }

    #[test]
    fn a_crossing_is_denied_until_a_rule_permits_it() {
        let mut l = ZoneLattice::new();
        let pair = (z("internal.apac"), z("partner.acme"));

        let denied = l.resolve(&pair.0, &pair.1);
        assert!(!denied.permitted);
        assert_eq!(denied.crossing, Crossing::Egress);
        assert!(denied.reason.contains("needs an explicit crossing rule"));

        l.permit(CrossingRule::between(
            Crossing::Egress,
            z("internal.apac"),
            z("partner.acme"),
        ));
        let allowed = l.resolve(&pair.0, &pair.1);
        assert!(allowed.permitted);
        assert!(allowed.reason.contains("permitted by rule"));

        // The rule is directional: permitting egress does not permit ingress.
        assert!(!l.resolve(&pair.1, &pair.0).permitted);
    }

    #[test]
    fn a_rule_covers_a_subtree_not_just_a_leaf() {
        // Requiring one rule per leaf produces policy files nobody keeps current.
        let mut l = ZoneLattice::new();
        l.permit(CrossingRule::between(
            Crossing::Egress,
            z("internal"),
            z("partner.acme"),
        ));
        assert!(l
            .resolve(&z("internal.apac.payments"), &z("partner.acme.settlement"))
            .permitted);
        assert!(
            !l.resolve(&z("internal.apac"), &z("partner.other")).permitted,
            "a different partner is not covered"
        );
    }

    #[test]
    fn public_is_never_reachable_by_a_same_level_rule() {
        // Public is classified before the ordering, so a `lateral` or `egress` rule
        // can never accidentally open it.
        let mut l = ZoneLattice::new();
        l.permit(CrossingRule::any(Crossing::Egress));
        l.permit(CrossingRule::any(Crossing::Lateral));
        assert!(!l.resolve(&z("internal.apac"), &z("public")).permitted);
        assert!(!l.resolve(&z("public"), &z("public.other")).permitted);

        l.permit(CrossingRule::any(Crossing::Public));
        assert!(l.resolve(&z("internal.apac"), &z("public")).permitted);
    }

    #[test]
    fn strict_membership_refuses_an_undeclared_zone() {
        let mut l = ZoneLattice::new();
        l.declare(&z("internal.apac"), TrustLevel::Internal).unwrap();

        // Off by default, because an estate mid-adoption has unclassified zones and
        // refusing them all at once is how a rollout stops.
        assert!(l.resolve(&z("internal.apac"), &z("internal.wild")).permitted);

        l.set_strict_membership(true);
        let d = l.resolve(&z("internal.apac"), &z("internal.wild"));
        assert!(!d.permitted);
        assert!(d.reason.contains("callee zone internal.wild is not declared"));

        // A declared ancestor is enough: declaring `internal.apac` covers its
        // subtree, which is how the namespace is meant to be used.
        assert!(l
            .resolve(&z("internal.apac"), &z("internal.apac.payments"))
            .permitted);
    }

    #[test]
    fn a_declaration_cannot_contradict_the_zone_id() {
        // The id appears in every contract, log line and register. Letting it
        // disagree with the declared trust level makes all of them lie.
        let mut l = ZoneLattice::new();
        let err = l.declare(&z("partner.acme"), TrustLevel::Internal).unwrap_err();
        assert_eq!(err.code(), Code::CONFIG_INVALID);
        assert!(err.to_string().contains("names trust level"));
        assert!(l.declare(&z("partner.acme"), TrustLevel::Partner).is_ok());
    }

    // --- lint --------------------------------------------------------------

    #[test]
    fn lint_catches_a_rule_that_can_never_match() {
        // A permission an operator believes they granted and did not.
        let mut l = ZoneLattice::new();
        l.permit(CrossingRule::between(
            Crossing::Egress,
            z("partner.acme"),
            z("internal.apac"),
        ));
        let problems = l.lint();
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].contains("declared egress but that pair is ingress"));
    }

    #[test]
    fn lint_flags_duplicates_and_a_blanket_public_rule() {
        let mut l = ZoneLattice::new();
        l.permit(CrossingRule::any(Crossing::Egress));
        l.permit(CrossingRule::any(Crossing::Egress));
        l.permit(CrossingRule::any(Crossing::Public));
        let problems = l.lint();
        assert!(problems.iter().any(|p| p.contains("duplicate")), "{problems:?}");
        assert!(
            problems.iter().any(|p| p.contains("blanket `public`")),
            "{problems:?}"
        );
    }

    #[test]
    fn a_clean_lattice_lints_clean() {
        let mut l = ZoneLattice::new();
        l.declare(&z("internal.apac"), TrustLevel::Internal).unwrap();
        l.permit(CrossingRule::between(
            Crossing::Egress,
            z("internal.apac"),
            z("partner.acme"),
        ));
        assert!(l.lint().is_empty());
    }

    // --- the trait ---------------------------------------------------------

    #[test]
    fn the_lattice_is_usable_as_a_zone_rule() {
        let mut l = ZoneLattice::new();
        l.permit(CrossingRule::between(
            Crossing::Egress,
            z("internal"),
            z("partner.acme"),
        ));
        let rule: &dyn ZoneRule = &l;
        assert!(rule.permits(&z("internal.apac"), &z("partner.acme")));
        assert!(!rule.permits(&z("internal.apac"), &z("partner.other")));
        assert!(rule.permits(&z("internal.apac"), &z("internal.emea")));
    }
}
