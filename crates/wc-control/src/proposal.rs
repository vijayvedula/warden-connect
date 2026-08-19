//! A contract proposal, reviewed as a pull request into one repository (rung 2).
//!
//! The simplest arrangement that still produces real consent, and it exists because the bilateral
//! path did not get adopted. That path asked a provider to publish an offer from its own repository
//! and a consumer to declare a need from its own, so a first contract needed two repositories, two
//! pipelines, branch protection on both and a verified shim before anybody saw anything work.
//!
//! Here there is **one repository**. A proposal is a file added by a pull request; the accountable
//! owner of the *called* party reviews and merges it; and that merge is the consent. Three
//! consequences worth stating, because each is why this is worth having:
//!
//! * **the approval is a reviewed merge**, verified against the source host — not a click this
//!   system asserts happened. Stronger evidence than a portal button, and it reuses the machinery
//!   `scm` and `authority` already provide;
//! * **write access is one repository**, not every consumer's. A control plane that could push to
//!   380 repositories is a worse thing to compromise than one that can read them;
//! * **git is the audit trail.** `git log` on that repository is who asked, who approved and when,
//!   in a form an auditor already knows how to read.
//!
//! # The owner check is the whole control
//!
//! Anyone can open a pull request. What makes a merge into this repository mean something is that
//! the approver is the **registered owner of the callee** — the accountable human named when the
//! server was registered, which `Entity.owner` has always required. Without that check a merge
//! approved by anybody with write access to the contracts repository would mint a contract against
//! somebody else's service, which is a privilege-escalation path dressed as a review.
//!
//! # What lives here and what does not
//!
//! The signed artifact stays in the control plane. This repository holds the *record* — what was
//! asked for, by whom, approved by whom — and never the JWS. A signed contract committed to a
//! repository is a bearer grant that stays cryptographically valid until its `exp` no matter what
//! the registry says, and git has no way to express "withdrawn". Revocation is the hard half of
//! this system and a copy in a repository quietly defeats it.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use wc_core::error::{Code, Result, WcError};
use wc_core::model::{EntityId, HumanRef};

/// How long a proposal asks for, when it does not say.
///
/// A day. Short enough that a forgotten contract lapses on its own, long enough that a working
/// agent is not re-minting hourly. A proposal that wants longer says so and an approver sees the
/// number in the diff, which is the point of the record being human-readable.
pub const DEFAULT_TTL_SECS: u64 = 86_400;

/// One proposed connection, as a file in the contracts repository.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Proposal {
    /// The calling party.
    pub caller: String,
    /// The called party. Its registered owner is who must approve.
    pub callee: String,
    /// Tools asked for. Empty is refused: a proposal for nothing reads as a proposal for
    /// everything to whoever skims the diff.
    #[serde(default)]
    pub tools: Vec<String>,
    /// Why. The only part written by a human for a human, and what an approver reads.
    pub justify: String,
    /// Requested lifetime, seconds. Capped by policy at mint time.
    #[serde(default)]
    pub ttl: Option<u64>,
    /// A change reference, when the estate wants one in the record.
    #[serde(default)]
    pub ticket: Option<String>,
}

impl Proposal {
    /// Parse one proposal file.
    pub fn parse(text: &str) -> Result<Proposal> {
        let p: Proposal = toml::from_str(text).map_err(|e| {
            WcError::with_detail(Code::POLICY_INVALID, "not a contract proposal").with_source(e)
        })?;
        p.validate()?;
        Ok(p)
    }

    fn validate(&self) -> Result<()> {
        if self.tools.is_empty() {
            return Err(WcError::with_detail(
                Code::SURFACE_NOT_SUBSET,
                format!(
                    "the proposal for {} lists no tools; an empty surface reads as though it asks \
                     for nothing and mints a contract that grants nothing",
                    self.callee
                ),
            ));
        }
        if self.justify.trim().len() < 12 {
            // A length floor rather than mere presence. `justify = "x"` satisfies a presence check
            // and tells an approver nothing, and this is the one field that exists for them.
            return Err(WcError::with_detail(
                Code::POLICY_INVALID,
                format!(
                    "the proposal for {} needs a justification an approver can act on; it is the \
                     only part of a contract written by a human for a human",
                    self.callee
                ),
            ));
        }
        EntityId::new(&self.caller)?;
        EntityId::new(&self.callee)?;
        Ok(())
    }

    /// The requested lifetime, or the default.
    #[must_use]
    pub fn ttl_secs(&self) -> u64 {
        self.ttl.unwrap_or(DEFAULT_TTL_SECS)
    }

    /// The contracted items, deduplicated and ordered.
    #[must_use]
    pub fn items(&self) -> BTreeSet<String> {
        self.tools.iter().cloned().collect()
    }
}

/// Why a proposal was not applied, in words an operator can act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// The file it came from.
    pub path: String,
    /// What was wrong.
    pub why: String,
}

/// Whether a merge's approvers include the callee's registered owner.
///
/// The control this whole arrangement rests on. `evidence.approvers` is what the source host says
/// approved the merge; `owner` is the accountable human recorded when the callee was registered.
/// A merge approved by somebody with write access but no ownership of the called service is not
/// consent from that service — it is a stranger agreeing on its behalf.
///
/// Matching is on the owner's identifier with any `human:` prefix removed, because a registry
/// records `human:priya@bank.com` and a source host reports the login or address it knows. That is
/// a mapping, and where it is wrong it is wrong in the safe direction: a mismatch refuses.
#[must_use]
pub fn owner_approved(approvers: &[String], owner: &HumanRef) -> bool {
    let want = owner.as_str().trim_start_matches("human:");
    approvers.iter().any(|a| {
        // Stripped on **both** sides. Stripping only the owner was the first version and it failed
        // its own test: a shim that reports the registry's form back verbatim would have been read
        // as a stranger. The prefix is this system's notation, not a name.
        let a = a.trim().trim_start_matches("human:");
        !a.is_empty() && a.eq_ignore_ascii_case(want)
    })
}

/// Why the owner check failed, for a refusal that names the fix.
#[must_use]
pub fn why_not_owner_approved(approvers: &[String], owner: &HumanRef) -> String {
    let want = owner.as_str().trim_start_matches("human:");
    if approvers.iter().all(|a| a.trim().is_empty()) {
        return format!(
            "the merge records no approvers, so nothing shows {want} agreed. A merge with no \
             review is not consent"
        );
    }
    format!(
        "the merge was approved by {}, and the callee's registered owner is {want}. Approval by \
         somebody with write access to this repository is not consent from the service they do not \
         own — ask {want} to review it, or correct the owner with `connect register`",
        approvers.join(", ")
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    const GOOD: &str = r#"
caller  = "spiffe://bank/ns/agents/sa/recon-bot"
callee  = "spiffe://bank/ns/svc/sa/payments-mcp"
tools   = ["get_balance"]
justify = "APAC reconciliation needs end-of-day balances"
"#;

    fn owner(s: &str) -> HumanRef {
        HumanRef::new(s).unwrap()
    }

    #[test]
    fn a_proposal_round_trips_and_defaults_its_ttl() {
        let p = Proposal::parse(GOOD).unwrap();
        assert_eq!(p.caller, "spiffe://bank/ns/agents/sa/recon-bot");
        assert_eq!(p.ttl_secs(), DEFAULT_TTL_SECS);
        assert_eq!(p.items().len(), 1);
    }

    #[test]
    fn an_empty_tool_list_is_refused() {
        // A proposal for nothing reads as a proposal for everything to whoever skims the diff.
        let text = GOOD.replace(r#"tools   = ["get_balance"]"#, "tools = []");
        assert_eq!(
            Proposal::parse(&text).unwrap_err().code(),
            Code::SURFACE_NOT_SUBSET
        );
    }

    #[test]
    fn a_justification_must_say_something() {
        // A presence check passes `justify = "x"`, which tells an approver nothing — and this is
        // the only field in the file that exists for them.
        let text = GOOD.replace(
            r#"justify = "APAC reconciliation needs end-of-day balances""#,
            r#"justify = "x""#,
        );
        assert!(Proposal::parse(&text).is_err());
    }

    #[test]
    fn an_unknown_field_is_refused_rather_than_ignored() {
        // `deny_unknown_fields`, because a misspelled `tool =` silently granting nothing is worse
        // than a parse error an author sees immediately.
        let text = format!("{GOOD}tool = [\"typo\"]\n");
        assert!(Proposal::parse(&text).is_err());
    }

    #[test]
    fn a_malformed_party_is_refused_at_parse_time() {
        let text = GOOD.replace("spiffe://bank/ns/agents/sa/recon-bot", "not an id");
        assert!(Proposal::parse(&text).is_err());
    }

    #[test]
    fn the_registered_owner_approving_is_what_counts() {
        let o = owner("human:priya@bank.com");
        assert!(owner_approved(&["priya@bank.com".to_string()], &o));
        // Case, because a source host reports the login it holds and a registry records what an
        // operator typed.
        assert!(owner_approved(&["Priya@Bank.com".to_string()], &o));
        // And the prefix, because the registry's form carries `human:` and no host reports that.
        assert!(owner_approved(&["human:priya@bank.com".to_string()], &o));
    }

    #[test]
    fn approval_by_anyone_else_is_not_consent() {
        // The privilege-escalation path this check closes: anybody with write access to the
        // contracts repository could otherwise mint a contract against a service they do not own.
        let o = owner("human:priya@bank.com");
        assert!(!owner_approved(&["cecil@bank.com".to_string()], &o));
        let why = why_not_owner_approved(&["cecil@bank.com".to_string()], &o);
        assert!(why.contains("cecil@bank.com"), "{why}");
        assert!(why.contains("priya@bank.com"), "{why}");
    }

    #[test]
    fn no_approvers_at_all_says_so_specifically() {
        // Distinguished from "the wrong person approved", because the fixes differ: one needs a
        // review, the other needs the right reviewer.
        let o = owner("human:priya@bank.com");
        assert!(!owner_approved(&[], &o));
        assert!(why_not_owner_approved(&[], &o).contains("no approvers"));
    }

    #[test]
    fn an_empty_approver_string_is_not_an_approver() {
        // A shim that reports `approvers: [""]` for an unreviewed merge — which the GitHub wrapper
        // does when its jq filter matches nothing — must not read as the owner having agreed.
        let o = owner("human:priya@bank.com");
        assert!(!owner_approved(&[String::new()], &o));
    }
}
