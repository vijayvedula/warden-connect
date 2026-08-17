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

    const MANIFEST: &str = "asset = \"spiffe://bank/ns/svc/sa/payments-mcp\"\n";

    /// A shim answering both verbs: a reviewed merge, and `file` returning `body`.
    fn shim_serving(tag: &str, body: &str) -> (Dir, ScmShim) {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD.encode(body);
        let d = Dir::new(tag);
        let s = d.shim(&format!(
            "read -r q\n\
             case \"$q\" in\n\
             *merge_evidence*) printf '%s\\n' '{{\"merged\":true,\"ref\":\"refs/heads/main\",\
             \"protected\":true,\"request_id\":\"214\",\"author\":\"r.mehta\",\
             \"approvers\":[\"s.iyer\"]}}' ;;\n\
             *) printf '%s\\n' '{{\"content_b64\":\"{b64}\"}}' ;;\n\
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
