//! Who is entitled to say a connection was approved (W5).
//!
//! The seam that replaces `ApproverRegistry` for the pipeline-driven path. That registry answers
//! *"does this signature come from a key with the right role"*, which is the right question when a
//! named human signs an approval artifact and the wrong one when both parties consented by
//! merging a reviewed change in their own repository.
//!
//! A trait rather than a concrete check, and the reason is forward-looking: a control function
//! that later wants a change record on tier-1 flows adds an adapter, and composition becomes a
//! policy rule instead of a schema change. One adapter ships — [`ScmMerge`].
//!
//! # What a consent has to establish
//!
//! Three things, and the third is the one that is easy to leave out:
//!
//! 1. the commit reached a **guarded** ref through a merge, approved by somebody other than its
//!    author — [`crate::scm::checked_evidence`];
//! 2. the pipeline presenting it is **registered to speak for that asset** — the caller's job,
//!    via [`crate::pipeline::PipelineRegistry`];
//! 3. the manifest being acted on is **the one that was reviewed**.
//!
//! Without the third, a pipeline could have a reviewed merge and then submit different content —
//! the review would constrain nothing, and the whole chain would be decorative. It is why the
//! shim protocol has a `file` verb at all.

use wc_core::contract::{MergeApproval, Side};
use wc_core::error::{Code, Result, WcError};
use wc_core::util::sha256_hex;

use serde::{Deserialize, Serialize};
use crate::pipeline::Asserted;
use crate::scm::ScmShim;

/// The manifest a consent is being claimed for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestBinding {
    /// Path within the repository, e.g. `warden/offer.toml`.
    pub path: String,
    /// Digest of the bytes the caller is acting on.
    pub digest: String,
}

impl ManifestBinding {
    /// Bind to the bytes a caller actually holds.
    #[must_use]
    pub fn of(path: &str, bytes: &str) -> ManifestBinding {
        ManifestBinding {
            path: path.to_string(),
            digest: format!("sha256:{}", sha256_hex(bytes)),
        }
    }
}

/// Who may approve a change to a manifest, declared in the manifest itself.
///
/// Read from the **base** commit of the merge, never the head. A pull request that adds its own
/// author to this list must not be approvable by that author: the list that governs a change is the
/// one that was already on the branch. Same rule GitHub applies to `CODEOWNERS`, and the reason is
/// the same — a self-referential approver list is not an approver list.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ApprovalBlock {
    /// Source-host logins entitled to approve. Compared case-insensitively, `human:` stripped on
    /// both sides so a registry-form entry and a host-form entry still match.
    #[serde(default)]
    pub approvers: Vec<String>,
    /// How many of them must approve. Defaults to one.
    #[serde(default = "one")]
    pub min: usize,
}

fn one() -> usize {
    1
}

impl ApprovalBlock {
    /// Which of `who` are declared here.
    #[must_use]
    pub fn declared<'a>(&self, who: &'a [String]) -> Vec<&'a String> {
        who.iter()
            .filter(|a| {
                let a = a.trim().trim_start_matches("human:");
                !a.is_empty()
                    && self.approvers.iter().any(|d| {
                        d.trim()
                            .trim_start_matches("human:")
                            .eq_ignore_ascii_case(a)
                    })
            })
            .collect()
    }

    /// Nobody can approve through an empty list, so an empty one is a refusal, not a default.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.approvers.iter().all(|a| a.trim().is_empty())
    }
}

/// Something entitled to say a party consented.
pub trait ApprovalAuthority {
    /// A short name recorded on the consent, so a report can say what vouched for it.
    fn name(&self) -> &str;

    /// Verify one side's consent, or refuse with a reason an operator can act on.
    fn consent(
        &self,
        side: Side,
        asserted: &Asserted,
        manifest: &ManifestBinding,
    ) -> Result<MergeApproval>;
}

/// Consent evidenced by a reviewed merge, read from a source host through a shim.
#[derive(Debug)]
pub struct ScmMerge<'a> {
    /// The shim to ask.
    pub shim: &'a ScmShim,
}

impl ScmMerge<'_> {
    /// `[approval]` as it stood on `base_sha`.
    ///
    /// Both manifests carry the block under the same key, so the TOML is parsed for that key alone
    /// rather than through `OfferManifest` or `NeedManifest`. Parsing the whole manifest here would
    /// make an unrelated schema change to either one able to break consent for both.
    fn declared_approvers(&self, repo: &str, base_sha: &str, path: &str) -> Result<ApprovalBlock> {
        #[derive(serde::Deserialize)]
        struct JustApproval {
            #[serde(default)]
            approval: Option<ApprovalBlock>,
        }
        let bytes = self.shim.file(repo, base_sha, path)?;
        let text = String::from_utf8_lossy(&bytes);
        let parsed: JustApproval = toml::from_str(&text).map_err(|e| {
            WcError::with_detail(
                Code::APPROVER_NOT_DECLARED,
                format!("{path} at {base_sha} is not readable TOML, so its [approval] cannot be read"),
            )
            .with_source(e)
        })?;
        Ok(parsed.approval.unwrap_or_default())
    }
}

impl ApprovalAuthority for ScmMerge<'_> {
    fn name(&self) -> &str {
        self.shim.label()
    }

    fn consent(
        &self,
        side: Side,
        asserted: &Asserted,
        manifest: &ManifestBinding,
    ) -> Result<MergeApproval> {
        // 1 · a reviewed merge of the commit that was asserted.
        let evidence = crate::scm::checked_evidence(self.shim, asserted)?;

        // 2 · the manifest at that commit is the one being acted on.
        //
        // The step that makes the review mean anything. A pipeline with a genuine reviewed merge
        // could otherwise submit content the reviewers never saw, and every check above it would
        // still pass.
        let reviewed = self
            .shim
            .file(&asserted.repo, &asserted.sha, &manifest.path)?;
        let reviewed_digest = format!("sha256:{}", sha256_hex(&String::from_utf8_lossy(&reviewed)));
        if reviewed_digest != manifest.digest {
            return Err(WcError::with_detail(
                Code::APPROVAL_SIGNATURE_INVALID,
                format!(
                    "{} at {} digests to {reviewed_digest}, and the content submitted digests to \
                     {}. A reviewed merge of a different file is not approval of this one",
                    manifest.path, asserted.sha, manifest.digest
                ),
            ));
        }

        // 3 · the approvers were declared, on the BASE commit.
        //
        // Head would let one pull request add its author to `[approval]` and be approved by them in
        // the same change. Base means joining the list and using it are two merges, and the first
        // is governed by whoever was already on it.
        if evidence.base_sha.trim().is_empty() {
            return Err(WcError::with_detail(
                Code::APPROVER_NOT_DECLARED,
                format!(
                    "{} did not report the base commit for {}, so the approver list cannot be read                      from anywhere but the merge itself — and a list read from the change it                      governs governs nothing",
                    self.name(),
                    asserted.sha
                ),
            ));
        }
        let declared = self.declared_approvers(&asserted.repo, &evidence.base_sha, &manifest.path)?;
        if declared.is_empty() {
            return Err(WcError::with_detail(
                Code::APPROVER_NOT_DECLARED,
                format!(
                    "{} at {} declares no [approval].approvers, so nobody is entitled to approve a                      change to it. An absent list is a refusal, not a default",
                    manifest.path, evidence.base_sha
                ),
            ));
        }
        let signed = declared.declared(&evidence.approvers);
        if signed.len() < declared.min {
            return Err(WcError::with_detail(
                if signed.is_empty() {
                    Code::APPROVER_NOT_DECLARED
                } else {
                    Code::APPROVAL_QUORUM_MISSING
                },
                format!(
                    "{} at {} requires {} of [{}]; the merge was approved by [{}], of whom {} \
                     {} declared",
                    manifest.path,
                    evidence.base_sha,
                    declared.min,
                    declared.approvers.join(", "),
                    evidence.approvers.join(", "),
                    signed.len(),
                    if signed.len() == 1 { "is" } else { "are" },
                ),
            ));
        }

        Ok(MergeApproval {
            side,
            repo: asserted.repo.clone(),
            sha: asserted.sha.clone(),
            request_id: evidence.request_id,
            author: evidence.author,
            approvers: evidence.approvers,
            via: self.name().to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use std::path::PathBuf;
    use std::time::Duration;

    struct Dir(PathBuf);

    impl Dir {
        fn new(tag: &str) -> Dir {
            use std::sync::atomic::{AtomicU32, Ordering};
            static N: AtomicU32 = AtomicU32::new(0);
            let n = N.fetch_add(1, Ordering::SeqCst);
            let p = std::env::temp_dir().join(format!("wc-auth-{}-{tag}-{n}", std::process::id()));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).unwrap();
            Dir(p)
        }
        fn shim(&self, body: &str) -> ScmShim {
            use std::os::unix::fs::PermissionsExt;
            let path = self.0.join("shim.sh");
            std::fs::write(&path, body).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            ScmShim::parse("gh", &format!("/bin/sh {}", path.display()))
                .unwrap()
                .with_timeout(Duration::from_secs(5))
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    const APPROVAL: &str = "[approval]\napprovers = [\"s.iyer\"]\n";
    const MANIFEST: &str = "asset = \"spiffe://bank/ns/svc/sa/payments-mcp\"\n[approval]\napprovers = [\"s.iyer\"]\n";

    /// A shim answering both verbs: a reviewed merge, and `file` returning `body` at every commit.
    fn shim_serving(tag: &str, body: &str) -> (Dir, ScmShim) {
        shim_serving_base(tag, body, body)
    }

    /// A shim whose `file` answer depends on the commit asked for.
    ///
    /// `head` at the merge commit, `base` at `base_sha`. The two differ only in tests that care
    /// which one the approver list came from — which is the property W8.3 exists to hold.
    fn shim_serving_base(tag: &str, head: &str, base: &str) -> (Dir, ScmShim) {
        use base64::Engine as _;
        let e = base64::engine::general_purpose::STANDARD;
        let (h64, b64) = (e.encode(head), e.encode(base));
        let d = Dir::new(tag);
        let s = d.shim(&format!(
            "read -r q\n\
             case \"$q\" in\n\
             *merge_evidence*) printf '%s\\n' '{{\"merged\":true,\"ref\":\"refs/heads/main\",\
             \"protected\":true,\"request_id\":\"214\",\"author\":\"r.mehta\",\
             \"approvers\":[\"s.iyer\"],\"base_sha\":\"ba5e000\"}}' ;;\n\
             *ba5e000*) printf '%s\\n' '{{\"content_b64\":\"{b64}\"}}' ;;\n\
             *) printf '%s\\n' '{{\"content_b64\":\"{h64}\"}}' ;;\n\
             esac\n"
        ));
        (d, s)
    }

    fn asserted() -> Asserted {
        Asserted {
            repo: "bank/payments-mcp".into(),
            git_ref: "refs/heads/main".into(),
            sha: "05e9bde".into(),
        }
    }

    #[test]
    fn a_reviewed_merge_of_the_submitted_manifest_is_a_consent() {
        let (_d, shim) = shim_serving("good", MANIFEST);
        let auth = ScmMerge { shim: &shim };
        let c = auth
            .consent(
                Side::Target,
                &asserted(),
                &ManifestBinding::of("warden/offer.toml", MANIFEST),
            )
            .unwrap();
        assert_eq!(c.side, Side::Target);
        assert_eq!(c.approvers, vec!["s.iyer".to_string()]);
        assert_eq!(c.request_id, "214");
        assert_eq!(c.via, "gh", "the consent must name what vouched for it");
    }

    #[test]
    fn an_approver_added_in_the_same_change_does_not_count() {
        // The whole reason the list is read at the base. Head content adds `newcomer` to
        // [approval] and `newcomer` approved the merge; base did not have them. If this passes,
        // the approver list describes the change instead of governing it, and anyone with write
        // access can approve their own manifest in one pull request.
        let head = "asset = \"spiffe://bank/ns/svc/sa/payments-mcp\"\n\
                    [approval]\napprovers = [\"s.iyer\", \"newcomer\"]\n";
        // The merge's only approver is the newcomer, declared at head but not at base.
        let d2 = Dir::new("addself-ev");
        let sh = d2.shim(&format!(
            "read -r q\n\
             case \"$q\" in\n\
             *merge_evidence*) printf '%s\\n' '{{\"merged\":true,\"ref\":\"refs/heads/main\",\
             \"protected\":true,\"request_id\":\"9\",\"author\":\"r.mehta\",\
             \"approvers\":[\"newcomer\"],\"base_sha\":\"ba5e000\"}}' ;;\n\
             *ba5e000*) printf '%s\\n' '{{\"content_b64\":\"{}\"}}' ;;\n\
             *) printf '%s\\n' '{{\"content_b64\":\"{}\"}}' ;;\n\
             esac\n",
            {
                use base64::Engine as _;
                base64::engine::general_purpose::STANDARD.encode(APPROVAL)
            },
            {
                use base64::Engine as _;
                base64::engine::general_purpose::STANDARD.encode(head)
            }
        ));
        let auth = ScmMerge { shim: &sh };
        let err = auth
            .consent(
                Side::Target,
                &asserted(),
                &ManifestBinding::of("warden/offer.toml", head),
            )
            .unwrap_err();
        assert_eq!(err.code(), Code::APPROVER_NOT_DECLARED);
        assert!(err.detail().contains("newcomer"), "{}", err.detail());
    }

    #[test]
    fn a_manifest_declaring_nobody_refuses() {
        // Absent is a refusal, not a default. A manifest with no [approval] would otherwise be
        // approvable by anyone the host let merge it.
        let bare = "asset = \"spiffe://bank/ns/svc/sa/payments-mcp\"\n";
        let (_d, shim) = shim_serving_base("nobody", bare, bare);
        let auth = ScmMerge { shim: &shim };
        let err = auth
            .consent(
                Side::Target,
                &asserted(),
                &ManifestBinding::of("warden/offer.toml", bare),
            )
            .unwrap_err();
        assert_eq!(err.code(), Code::APPROVER_NOT_DECLARED);
        assert!(
            err.detail().contains("refusal, not a default"),
            "{}",
            err.detail()
        );
    }

    #[test]
    fn quorum_is_counted_against_declared_approvers_only() {
        // min = 2 with one declared approver signing. The second approver on the merge is real but
        // undeclared, so it must not count toward the quorum.
        let m = "asset = \"spiffe://bank/ns/svc/sa/payments-mcp\"\n\
                 [approval]\napprovers = [\"s.iyer\", \"p.rao\"]\nmin = 2\n";
        let (_d, shim) = shim_serving_base("quorum", m, m);
        let auth = ScmMerge { shim: &shim };
        let err = auth
            .consent(
                Side::Target,
                &asserted(),
                &ManifestBinding::of("warden/offer.toml", m),
            )
            .unwrap_err();
        assert_eq!(err.code(), Code::APPROVAL_QUORUM_MISSING);
        assert!(err.detail().contains("requires 2"), "{}", err.detail());
    }

    #[test]
    fn a_host_that_does_not_report_a_base_refuses_rather_than_reading_head() {
        // Falling back to head would silently reinstate exactly the hole the base read closes.
        // The manifest itself is served correctly, so the digest check passes and the refusal
        // that lands is the one under test rather than an earlier step.
        let d = Dir::new("nobase");
        let b64 = {
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD.encode(MANIFEST)
        };
        let sh = d.shim(&format!(
            "read -r q\n\
             case \"$q\" in\n\
             *merge_evidence*) printf '%s\\n' '{{\"merged\":true,\"ref\":\"refs/heads/main\",\
             \"protected\":true,\"request_id\":\"1\",\"author\":\"r.mehta\",\
             \"approvers\":[\"s.iyer\"]}}' ;;\n\
             *) printf '%s\\n' '{{\"content_b64\":\"{b64}\"}}' ;;\n\
             esac\n"
        ));
        let auth = ScmMerge { shim: &sh };
        let err = auth
            .consent(
                Side::Target,
                &asserted(),
                &ManifestBinding::of("warden/offer.toml", MANIFEST),
            )
            .unwrap_err();
        assert_eq!(err.code(), Code::APPROVER_NOT_DECLARED);
        assert!(
            err.detail().contains("governs nothing"),
            "{}",
            err.detail()
        );
    }

    #[test]
    fn the_declared_comparison_ignores_case_and_the_human_prefix() {
        let b = ApprovalBlock {
            approvers: vec!["human:S.Iyer".into()],
            min: 1,
        };
        assert_eq!(b.declared(&["s.iyer".to_string()]).len(), 1);
        assert_eq!(b.declared(&["human:s.iyer".to_string()]).len(), 1);
        assert_eq!(b.declared(&["someone".to_string()]).len(), 0);
        assert_eq!(b.declared(&[String::new()]).len(), 0);
    }

    #[test]
    fn a_reviewed_merge_of_different_content_is_not_approval_of_this_content() {
        // The check that makes the review mean anything. Without it a pipeline with a genuine
        // reviewed merge could submit whatever it liked and every other check would still pass.
        let (_d, shim) = shim_serving("swapped", "asset = \"spiffe://bank/ns/svc/sa/other\"\n");
        let auth = ScmMerge { shim: &shim };
        let err = auth
            .consent(
                Side::Target,
                &asserted(),
                &ManifestBinding::of("warden/offer.toml", MANIFEST),
            )
            .unwrap_err();
        assert_eq!(err.code(), Code::APPROVAL_SIGNATURE_INVALID);
        assert!(
            err.detail().contains("not approval of this one"),
            "{}",
            err.detail()
        );
    }

    #[test]
    fn an_unreviewed_merge_is_refused_before_the_manifest_is_even_fetched() {
        let d = Dir::new("selfapproved");
        let shim = d.shim(
            "read -r q\n\
             printf '%s\\n' '{\"merged\":true,\"ref\":\"refs/heads/main\",\"protected\":true,\
             \"author\":\"a.khan\",\"approvers\":[\"a.khan\"]}'\n",
        );
        let auth = ScmMerge { shim: &shim };
        let err = auth
            .consent(
                Side::Source,
                &asserted(),
                &ManifestBinding::of("warden/connections.toml", MANIFEST),
            )
            .unwrap_err();
        assert!(err.detail().contains("two hats"), "{}", err.detail());
    }

    #[test]
    fn a_binding_digests_the_bytes_it_was_given() {
        let a = ManifestBinding::of("p", MANIFEST);
        let b = ManifestBinding::of("p", MANIFEST);
        let c = ManifestBinding::of("p", "different");
        assert_eq!(a, b, "the same bytes must bind identically");
        assert_ne!(a.digest, c.digest);
        assert!(a.digest.starts_with("sha256:"));
    }

    // --- the approval itself -------------------------------------------------

    fn consent(side: Side, author: &str, approvers: &[&str]) -> MergeApproval {
        MergeApproval {
            side,
            repo: "bank/x".into(),
            sha: "abc".into(),
            request_id: "1".into(),
            author: author.into(),
            approvers: approvers.iter().map(|s| (*s).to_string()).collect(),
            via: "gh".into(),
        }
    }

    #[test]
    fn a_reviewed_merge_approval_needs_a_consent_from_each_side() {
        use wc_core::contract::ApprovalRef;
        // One side alone is a request, not an agreement — and this mode's entire claim is that
        // both parties agreed. A struct literal could not refuse this, which is why there is a
        // named constructor.
        let only_source = ApprovalRef::reviewed_merge(vec![consent(Side::Source, "a", &["b"])]);
        assert!(only_source.is_err());
        let only_target = ApprovalRef::reviewed_merge(vec![consent(Side::Target, "a", &["b"])]);
        assert!(only_target.is_err());

        let both = ApprovalRef::reviewed_merge(vec![
            consent(Side::Source, "a", &["b"]),
            consent(Side::Target, "c", &["d"]),
        ])
        .unwrap();
        assert!(both.consent_from(Side::Source).is_some());
        assert!(both.consent_from(Side::Target).is_some());
    }

    #[test]
    fn a_self_approved_side_is_refused_at_construction_too() {
        use wc_core::contract::ApprovalRef;
        // Belt and braces: the authority already refuses this, and so does the type. A consent
        // that reached the constructor by another route must not become an approval.
        let err = ApprovalRef::reviewed_merge(vec![
            consent(Side::Source, "a.khan", &["a.khan"]),
            consent(Side::Target, "c", &["d"]),
        ])
        .unwrap_err();
        assert!(
            err.detail().contains("distinct from its author"),
            "{}",
            err.detail()
        );
    }

    #[test]
    fn a_reviewed_merge_contract_is_renewable_unlike_break_glass() {
        use wc_core::contract::ApprovalRef;
        let a = ApprovalRef::reviewed_merge(vec![
            consent(Side::Source, "a", &["b"]),
            consent(Side::Target, "c", &["d"]),
        ])
        .unwrap();
        assert!(
            a.is_renewable(),
            "a reviewed merge is the normal path; only break-glass is unrenewable"
        );
    }

    #[test]
    fn the_consents_survive_the_wire_because_an_audit_asks_which_commit() {
        use wc_core::contract::ApprovalRef;
        let a = ApprovalRef::reviewed_merge(vec![
            consent(Side::Source, "a.khan", &["t.ross"]),
            consent(Side::Target, "r.mehta", &["s.iyer"]),
        ])
        .unwrap();
        let back: ApprovalRef = serde_json::from_str(&serde_json::to_string(&a).unwrap()).unwrap();
        assert_eq!(back, a);
        assert_eq!(
            back.consent_from(Side::Target).unwrap().approvers,
            vec!["s.iyer"]
        );
    }

    #[test]
    fn an_older_approval_with_no_merges_still_deserialises() {
        use wc_core::contract::ApprovalRef;
        // `merges` is additive and defaulted so PAYLOAD_SCHEMA can stay at 1 — verification
        // compares the schema exactly, and bumping it would make every deployed mediator refuse
        // every new contract.
        let old = r#"{"by":null,"jti":null,"ticket":null,"mode":"standing_policy","second":null}"#;
        let a: ApprovalRef = serde_json::from_str(old).unwrap();
        assert!(a.merges.is_empty());
    }

    #[test]
    fn a_key_backed_human_approval_records_no_merge_evidence() {
        use wc_core::contract::{ApprovalMode, ApprovalRef};
        // The two modes must stay distinguishable in a report: `Human` means a signature over
        // these terms, `ReviewedMerge` means evidence about a process. An empty list is how a
        // reader tells them apart without consulting the mode.
        let standing = ApprovalRef::standing();
        assert!(standing.merges.is_empty());
        assert_eq!(standing.mode, ApprovalMode::StandingPolicy);
    }
}
