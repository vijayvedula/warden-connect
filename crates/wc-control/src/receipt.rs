//! Contract receipts — what goes back to a repository, and what never does.
//!
//! # The signed artifact is never committed
//!
//! A contract is a signed JWS that verifies until its `exp`, whatever the registry says afterwards.
//! Committing one to a repository would put a **bearer grant** in git: revoke the contract and the
//! file still verifies, and git has no way to express "withdrawn" — a deletion is just another
//! commit, and the blob remains reachable. Anyone who can read the history holds a working grant
//! until it expires on its own.
//!
//! So a receipt goes back instead: a human-readable record that a connection exists, carrying no
//! key material and no signature, and granting nothing. It is evidence for people, not for
//! machines. The authoritative copy stays in the state log, where revocation means something.
//!
//! # Why write anything back at all
//!
//! Because the question "what is this repository allowed to call?" should be answerable in the
//! repository. Today it is answerable only by someone with access to the control plane, which makes
//! the connection invisible to the team that owns the code and to any auditor reading the repo.
//! A receipt closes that without moving the authority.

use wc_core::contract::{ContractRecord, ContractStatus};

/// The path a receipt is written to, inside the repository it concerns.
///
/// Reserved like the manifests, and for the same reason: a fixed location means the answer to "what
/// may this repository call" is in one predictable place rather than wherever somebody put it.
pub const RECEIPT_DIR: &str = "warden/contracts";

/// The file name for one connection's receipt.
#[must_use]
pub fn receipt_path(record: &ContractRecord) -> String {
    format!("{RECEIPT_DIR}/{}.toml", record.cid.as_str())
}

/// Render a receipt for one contract.
///
/// Deterministic: the same record renders byte for byte, so a re-run proposes nothing. Sorted item
/// lists for the same reason.
#[must_use]
pub fn render(record: &ContractRecord) -> String {
    // `Surface::items` already sorts and dedups. An extra sort here was dead code: mutation testing
    // removed it and nothing failed, which is what dead code looks like from the outside.
    let items = record.surface.items();

    let mut out = String::with_capacity(1024);
    out.push_str("# warden-connect contract receipt — generated, do not edit\n#\n");
    out.push_str(
        "# This is a RECORD, not a grant. It carries no signature and no key, and holding\n",
    );
    out.push_str("# it permits nothing. The contract itself is a signed artifact held by the\n");
    out.push_str(
        "# control plane, and is deliberately NOT committed here: a signed contract in git\n",
    );
    out.push_str("# verifies until its expiry no matter what the registry says, and git cannot\n");
    out.push_str("# express \"withdrawn\".\n#\n");
    out.push_str("# To check whether this connection is still live:\n");
    out.push_str(&format!("#     connect show {}\n#\n", record.cid.as_str()));

    out.push_str(&format!("cid            = {}\n", q(record.cid.as_str())));
    out.push_str(&format!("artifact       = {}\n", q(record.jti.as_str())));
    out.push_str(&format!("caller         = {}\n", q(record.caller.as_str())));
    out.push_str(&format!("callee         = {}\n", q(record.callee.as_str())));
    out.push_str(&format!(
        "caller_zone    = {}\n",
        q(record.caller_zone.as_str())
    ));
    out.push_str(&format!(
        "callee_zone    = {}\n",
        q(record.callee_zone.as_str())
    ));
    out.push_str("items          = [");
    for (i, it) in items.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        out.push_str(&q(it));
    }
    out.push_str("]\n");
    out.push_str(&format!("surface_digest = {}\n", q(&record.surface_digest)));
    // The DIGEST of the artifact, never the artifact. It lets a reader confirm the control plane's
    // copy is the one this receipt describes, and it grants nothing on its own.
    out.push_str(&format!("jws_sha256     = {}\n", q(&record.jws_sha256)));
    out.push_str(&format!("issued_at      = {}\n", record.iat));
    out.push_str(&format!(
        "expires_at     = {}  # {}\n",
        record.exp,
        crate::export::iso8601(record.exp)
    ));
    out.push_str(&format!(
        "status         = {}\n",
        q(status_str(record.status))
    ));
    out.push_str(&format!("policy_version = {}\n", q(&record.policy_version)));
    if let Some(v) = record.offer_version {
        out.push_str(&format!("offer_version  = {v}\n"));
    }

    out.push_str("\n[approval]\n");
    out.push_str(&format!(
        "mode = {}\n",
        q(&format!("{:?}", record.approval.mode))
    ));
    if let Some(by) = &record.approval.by {
        out.push_str(&format!("by   = {}\n", q(by.as_str())));
    }
    if let Some(second) = &record.approval.second {
        out.push_str(&format!("second = {}\n", q(second.as_str())));
    }
    if let Some(t) = &record.approval.ticket {
        out.push_str(&format!("ticket = {}\n", q(t)));
    }
    // The merges are the interesting part for anybody reading this in the repository: they point at
    // the pull requests where the consent actually happened, which is where an auditor should look
    // rather than at this file.
    for m in &record.approval.merges {
        out.push_str("\n[[approval.merge]]\n");
        out.push_str(&format!("side       = {}\n", q(&format!("{:?}", m.side))));
        out.push_str(&format!("repo       = {}\n", q(&m.repo)));
        out.push_str(&format!("sha        = {}\n", q(&m.sha)));
        out.push_str(&format!("request_id = {}\n", q(&m.request_id)));
        out.push_str(&format!("author     = {}\n", q(&m.author)));
        out.push_str("approvers  = [");
        let mut approvers = m.approvers.clone();
        approvers.sort();
        for (i, a) in approvers.iter().enumerate() {
            if i > 0 {
                out.push_str(", ");
            }
            out.push_str(&q(a));
        }
        out.push_str("]\n");
        out.push_str(&format!("via        = {}\n", q(&m.via)));
    }
    out
}

fn status_str(s: ContractStatus) -> &'static str {
    match s {
        ContractStatus::Active => "active",
        ContractStatus::Suspended => "suspended",
        ContractStatus::Revoked => "revoked",
    }
}

/// A TOML basic string.
fn q(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04X}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use wc_core::contract::{ApprovalMode, ApprovalRef, MergeApproval, Side, Surface, Terms};
    use wc_core::model::{Cid, EntityId, HumanRef, Jti, Tier, ZoneId};

    fn record() -> ContractRecord {
        ContractRecord {
            cid: Cid::new("conn_abcdef12").unwrap(),
            jti: Jti::new("cx_abcdef1234567890").unwrap(),
            caller: EntityId::new("urn:acme:repo:recon").unwrap(),
            callee: EntityId::new("urn:acme:mcp:pay").unwrap(),
            caller_zone: ZoneId::new("internal.apac").unwrap(),
            callee_zone: ZoneId::new("internal.payments").unwrap(),
            callee_tier: Tier::TWO,
            callee_manifest: "sha256:m1".to_string(),
            surface_digest: "sha256:sd".to_string(),
            surface: Surface {
                tools: vec!["transfer_funds".to_string(), "get_balance".to_string()],
                skills: Vec::new(),
                resources: Vec::new(),
            },
            terms: Terms::default(),
            aud: vec!["warden:mediator:one".to_string()],
            jws_sha256: "sha256:jjjj".to_string(),
            schema: 1,
            status: ContractStatus::Active,
            approval: ApprovalRef {
                by: Some(HumanRef::new("human:owner@bank").unwrap()),
                jti: None,
                ticket: None,
                mode: ApprovalMode::Human,
                second: None,
                merges: vec![MergeApproval {
                    side: Side::Target,
                    repo: "bank/payments-mcp".to_string(),
                    sha: "abc123".to_string(),
                    request_id: "412".to_string(),
                    author: "dev@bank".to_string(),
                    // Two, out of order, so the sort is observable. One approver made it a no-op
                    // and mutation testing could not tell the sort from its absence.
                    approvers: vec!["zoe@bank".to_string(), "owner@bank".to_string()],
                    via: "gh".to_string(),
                                bootstrap: false,
            }],
            },
            policy_version: "live@v1".to_string(),
            iat: 1_787_000_000,
            exp: 1_787_003_600,
            offer_version: Some(3),
        }
    }

    #[test]
    fn a_receipt_carries_no_signature_and_no_key() {
        // The whole reason a receipt exists rather than the artifact. A JWS here would be a bearer
        // grant in git, valid until its expiry however the registry is changed afterwards.
        let out = render(&record());
        assert!(!out.contains("eyJ"), "a JWS appeared: {out}");
        assert!(!out.contains("BEGIN"), "PEM material appeared: {out}");
        assert!(out.contains("carries no signature and no key"));
        assert!(
            out.contains("connect show conn_abcdef12"),
            "no way to check it"
        );
    }

    #[test]
    fn a_receipt_is_valid_toml_and_deterministic() {
        let a = render(&record());
        let b = render(&record());
        assert_eq!(a, b, "two renders of one record must agree byte for byte");
        let parsed: toml::Value = toml::from_str(&a).expect("must parse");
        assert_eq!(parsed["cid"].as_str(), Some("conn_abcdef12"));
        // Sorted by `Surface::items`, which is where the guarantee lives — asserted here because
        // determinism of this file depends on it, not because this function does the sorting.
        assert_eq!(
            parsed["items"].as_array().unwrap()[0].as_str(),
            Some("get_balance"),
            "items must be sorted, not in record order"
        );
    }

    #[test]
    fn the_merge_that_approved_it_is_named() {
        // Where an auditor should actually look. The receipt is a pointer to the consent, not the
        // consent itself.
        let out = render(&record());
        let parsed: toml::Value = toml::from_str(&out).expect("must parse");
        let m = &parsed["approval"]["merge"].as_array().unwrap()[0];
        assert_eq!(m["repo"].as_str(), Some("bank/payments-mcp"));
        assert_eq!(m["request_id"].as_str(), Some("412"));
        assert_eq!(m["author"].as_str(), Some("dev@bank"));
        // Sorted, so a re-run of an unchanged contract proposes nothing.
        let approvers: Vec<&str> = m["approvers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(approvers, vec!["owner@bank", "zoe@bank"]);
    }

    #[test]
    fn a_hostile_string_in_a_host_supplied_field_cannot_break_the_file() {
        // `author`, `approvers` and `ticket` come from a source host or an operator. An unescaped
        // quote would make the receipt unparseable at best, and at worst change which keys it
        // defines — a receipt that parses as something else is worse than one that fails to parse.
        let mut r = record();
        r.approval.ticket = Some("CHG-1\" evil = \"yes".to_string());
        if let Some(m) = r.approval.merges.first_mut() {
            m.author = "a\"b\\c\nd".to_string();
        }
        let out = render(&r);
        let parsed: toml::Value = toml::from_str(&out).expect("must still be valid TOML");
        assert_eq!(
            parsed["approval"]["ticket"].as_str(),
            Some("CHG-1\" evil = \"yes"),
            "the ticket did not round-trip"
        );
        assert!(
            parsed["approval"].get("evil").is_none(),
            "the payload defined a key of its own"
        );
        assert_eq!(
            parsed["approval"]["merge"].as_array().unwrap()[0]["author"].as_str(),
            Some("a\"b\\c\nd")
        );
    }

    #[test]
    fn the_path_is_reserved_and_derived_from_the_cid() {
        // One predictable place, so "what may this repository call" is answerable by looking rather
        // than by asking.
        assert_eq!(
            receipt_path(&record()),
            "warden/contracts/conn_abcdef12.toml"
        );
    }
}
