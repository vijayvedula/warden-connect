//! Which pipeline is asking, and may it speak for this asset? (W3)
//!
//! Distinct from §8.7.1 stage 1, and the distinction is the whole design. Stage 1 asks *"is this
//! workload the party it claims to be"*. This asks two different questions:
//!
//! 1. **Who is calling?** A pipeline authenticates with its platform's workload identity.
//! 2. **What was reviewed?** A repository, a ref, and a commit.
//!
//! Those were one question in the first design sketch, because GitHub Actions bundles both into
//! one token and it is easy to mistake that for the general case. It is not. Azure DevOps issues
//! `sc://org/project/connection`, and AWS CodeBuild and Google Cloud Build authenticate a *role*
//! or a *service account* with no commit anywhere in the credential. Treating those tokens as
//! though they proved a commit would be a control that reads as configured and does nothing —
//! this repository's recurring defect, applied to the thing that decides what gets deployed.
//!
//! So the two facts are carried separately, and how well the second one is known is part of the
//! type: see [`SourceBinding`]. Policy states the bar, and adding a weak provider cannot silently
//! lower it, because the weakening is a value the policy has to permit.
//!
//! # Registration is explicit, never a glob
//!
//! [`PipelineRegistry`] maps an asset to the principals allowed to speak for it. A pattern over
//! repository names is how a repository called `payments-mcp-test` publishes an offer for
//! `payments-mcp`. It also makes "who may publish for this asset" a question with an auditable
//! answer, which is the first thing a control function asks.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use wc_core::error::{Code, Result, WcError};
use wc_core::model::EntityId;

/// Where the source facts came from, and therefore how much they are worth.
///
/// Ordered by strength so a policy can demand a floor. The point of the distinction is that
/// three of the six supported CI platforms cannot prove a commit in their credential at all, and
/// pretending otherwise would make a deploy gate decorative.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum SourceBinding {
    /// The commit and ref are **inside the verified token**. Nothing is taken on trust.
    Proven {
        /// Opaque repository identifier — never parsed.
        repo: String,
        /// The git ref, e.g. `refs/heads/main`.
        git_ref: String,
        /// The commit.
        sha: String,
    },
    /// Asserted by the caller, then **re-read from the source host** and found to match.
    ///
    /// Trust moves from the CI platform to the source host, which is where it belongs: the
    /// pipeline cannot lie about the commit because somebody looked.
    Verified {
        /// Opaque repository identifier.
        repo: String,
        /// The git ref.
        git_ref: String,
        /// The commit.
        sha: String,
    },
    /// Asserted by the caller and **not checked**. Acceptable in non-production, and a policy
    /// that permits it in production has decided to trust its pipelines.
    Asserted {
        /// Opaque repository identifier.
        repo: String,
        /// The git ref.
        git_ref: String,
        /// The commit.
        sha: String,
    },
    /// No source facts at all — a registered key, or a platform with nothing to offer.
    None,
}

impl SourceBinding {
    /// Strength, for comparing against a policy floor. Higher is stronger.
    #[must_use]
    pub fn strength(&self) -> u8 {
        match self {
            SourceBinding::Proven { .. } => 3,
            SourceBinding::Verified { .. } => 2,
            SourceBinding::Asserted { .. } => 1,
            SourceBinding::None => 0,
        }
    }

    /// Whether this binding meets a required floor.
    #[must_use]
    pub fn meets(&self, floor: &SourceBinding) -> bool {
        self.strength() >= floor.strength()
    }

    /// The commit, when there is one.
    #[must_use]
    pub fn sha(&self) -> Option<&str> {
        match self {
            SourceBinding::Proven { sha, .. }
            | SourceBinding::Verified { sha, .. }
            | SourceBinding::Asserted { sha, .. } => Some(sha),
            SourceBinding::None => None,
        }
    }

    /// The ref, when there is one.
    #[must_use]
    pub fn git_ref(&self) -> Option<&str> {
        match self {
            SourceBinding::Proven { git_ref, .. }
            | SourceBinding::Verified { git_ref, .. }
            | SourceBinding::Asserted { git_ref, .. } => Some(git_ref),
            SourceBinding::None => None,
        }
    }

    /// The repository, when there is one.
    #[must_use]
    pub fn repo(&self) -> Option<&str> {
        match self {
            SourceBinding::Proven { repo, .. }
            | SourceBinding::Verified { repo, .. }
            | SourceBinding::Asserted { repo, .. } => Some(repo),
            SourceBinding::None => None,
        }
    }
}

/// A CI platform, and what its token can be relied on to say.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    /// `sub` is `repo:O/R:ref:refs/heads/main`, plus `sha`. Proves the commit.
    GitHubActions,
    /// Carries `project_path`, `ref`, `sha` and an explicit `ref_protected`.
    GitLabCi,
    /// Repository is addressed by UUID; branch information varies by tenant.
    BitbucketPipelines,
    /// `sub` is `sc://org/project/connection` — identifies a service connection, not a commit.
    AzureDevOps,
    /// A service-account token. No commit in the credential.
    GoogleCloudBuild,
}

impl Platform {
    /// The short label folded into a derived principal, keeping platforms apart.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Platform::GitHubActions => "gh",
            Platform::GitLabCi => "gl",
            Platform::BitbucketPipelines => "bb",
            Platform::AzureDevOps => "ado",
            Platform::GoogleCloudBuild => "gcb",
        }
    }

    /// Which claim carries the principal.
    #[must_use]
    pub fn subject_claim(self) -> &'static str {
        match self {
            // A service account's usable name is its email, not its numeric subject.
            Platform::GoogleCloudBuild => "email",
            _ => "sub",
        }
    }

    /// Extract the source facts this platform's token actually carries.
    ///
    /// `asserted` is what the caller claims, used only where the token cannot say. A platform
    /// that *can* say is never allowed to be overridden by an assertion — otherwise the strong
    /// platforms would be as weak as the weak ones whenever a caller lied.
    #[must_use]
    pub fn binding_from(
        self,
        claims: &Map<String, Value>,
        asserted: Option<&Asserted>,
    ) -> SourceBinding {
        let s = |k: &str| {
            claims
                .get(k)
                .and_then(Value::as_str)
                .map(str::to_string)
                .filter(|v| !v.is_empty())
        };
        match self {
            Platform::GitHubActions => match (s("repository"), s("ref"), s("sha")) {
                (Some(repo), Some(git_ref), Some(sha)) => {
                    SourceBinding::Proven { repo, git_ref, sha }
                }
                _ => SourceBinding::None,
            },
            Platform::GitLabCi => match (s("project_path"), s("ref"), s("sha")) {
                (Some(repo), Some(git_ref), Some(sha)) => {
                    // `ref_protected` is a string on the wire, not a bool. A protected ref is
                    // the only thing that makes a merge evidence of review, so an unprotected
                    // one is deliberately not `Proven`.
                    if claims.get("ref_protected").and_then(Value::as_str) == Some("true") {
                        SourceBinding::Proven { repo, git_ref, sha }
                    } else {
                        SourceBinding::Asserted { repo, git_ref, sha }
                    }
                }
                _ => SourceBinding::None,
            },
            // These three cannot prove a commit. Whatever the caller says is `Asserted` until
            // something re-reads it from the source host, which is what raises it to `Verified`.
            Platform::BitbucketPipelines | Platform::AzureDevOps | Platform::GoogleCloudBuild => {
                asserted.map_or(SourceBinding::None, |a| SourceBinding::Asserted {
                    repo: a.repo.clone(),
                    git_ref: a.git_ref.clone(),
                    sha: a.sha.clone(),
                })
            }
        }
    }
}

/// Source facts a caller asserts, for platforms whose token cannot carry them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Asserted {
    /// Opaque repository identifier.
    pub repo: String,
    /// The git ref.
    pub git_ref: String,
    /// The commit.
    pub sha: String,
}

/// An authenticated pipeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PipelineIdentity {
    /// The derived principal — `urn:wc:ci:<label>:<subject>`.
    ///
    /// Derived, never asserted, and the platform label is folded in: two platforms minting the
    /// same subject are two principals. Without the label, an Azure service connection named
    /// like a GitHub repository path would collide with it.
    pub principal: String,
    /// Which platform vouched.
    pub platform: Platform,
    /// What is known about the source, and how well.
    pub binding: SourceBinding,
    /// The issuer that verified the token, recorded so an audit can see the chain.
    pub authority: String,
}

/// Derive a principal from a platform label and a verified subject.
///
/// Refuses a label containing `:` for the reason `attest.rs` gives about its own derivation: it
/// would make the result ambiguous, so two different principals could render identically.
pub fn principal_for(label: &str, subject: &str) -> Result<String> {
    if label.is_empty() || label.contains(':') {
        return Err(WcError::with_detail(
            Code::CONFIG_INVALID,
            format!("platform label {label:?} must be non-empty and contain no ':'"),
        ));
    }
    let subject = subject.trim();
    if subject.is_empty() {
        return Err(WcError::with_detail(
            Code::IDENTITY_UNVERIFIABLE,
            "the verified token carries no principal claim",
        ));
    }
    Ok(format!("urn:wc:ci:{label}:{subject}"))
}

/// Which principals may speak for which assets.
///
/// Explicit entries only. A glob over repository names is how `payments-mcp-test` publishes an
/// offer for `payments-mcp`, and the blast radius of that is every consumer of the real one.
#[derive(Debug, Default, Clone, Deserialize, Serialize)]
pub struct PipelineRegistry {
    /// Asset → the principals allowed to act for it.
    #[serde(default)]
    pub entries: BTreeMap<String, BTreeSet<String>>,
}

impl PipelineRegistry {
    /// Parse from TOML.
    pub fn parse(text: &str) -> Result<PipelineRegistry> {
        toml::from_str(text).map_err(|e| {
            WcError::with_detail(Code::CONFIG_INVALID, format!("pipeline registry: {e}"))
                .with_source(e)
        })
    }

    /// Allow a principal to speak for an asset.
    pub fn allow(&mut self, asset: &EntityId, principal: &str) {
        self.entries
            .entry(asset.as_str().to_string())
            .or_default()
            .insert(principal.to_string());
    }

    /// Whether this pipeline may act for this asset.
    ///
    /// Exact match. No prefixes, no wildcards, no normalisation — an opaque string compared
    /// whole, because three of four supported source hosts have identifier shapes that any
    /// clever matching would get wrong.
    #[must_use]
    pub fn may_speak_for(&self, principal: &str, asset: &EntityId) -> bool {
        self.entries
            .get(asset.as_str())
            .is_some_and(|set| set.contains(principal))
    }

    /// Refuse with a reason an operator can act on.
    pub fn authorise(&self, identity: &PipelineIdentity, asset: &EntityId) -> Result<()> {
        if self.may_speak_for(&identity.principal, asset) {
            return Ok(());
        }
        let known = self.entries.get(asset.as_str()).map_or(0, BTreeSet::len);
        Err(WcError::with_detail(
            Code::IDENTITY_UNVERIFIABLE,
            format!(
                "{} is not registered to act for {asset} ({known} principal(s) are). Register it \
                 explicitly — patterns are refused, because a repository named like another one \
                 would inherit its permissions",
                identity.principal
            ),
        ))
    }
}

/// Verify a pipeline's OIDC token and derive its identity.
///
/// The JWT verification is [`crate::attest::OidcIdentity::verified_claims`] — pinned issuer, key
/// chosen by `kid`, audience bound, injected clock — reused rather than reimplemented, because a
/// second copy of that is how one of them ends up weaker.
pub fn identify_oidc(
    verifier: &crate::attest::OidcIdentity<'_>,
    platform: Platform,
    asserted: Option<&Asserted>,
) -> Result<PipelineIdentity> {
    let (claims, _kid) = verifier.verified_claims()?;
    let subject = claims
        .get(platform.subject_claim())
        .and_then(Value::as_str)
        .unwrap_or_default();
    Ok(PipelineIdentity {
        principal: principal_for(platform.label(), subject)?,
        platform,
        binding: platform.binding_from(&claims, asserted),
        authority: verifier.issuer.clone(),
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use serde_json::json;

    fn claims(pairs: &[(&str, &str)]) -> Map<String, Value> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), json!(v)))
            .collect()
    }

    fn asserted() -> Asserted {
        Asserted {
            repo: "bank/payments-mcp".into(),
            git_ref: "refs/heads/main".into(),
            sha: "05e9bde".into(),
        }
    }

    #[test]
    fn github_proves_the_commit_from_its_own_token() {
        let b = Platform::GitHubActions.binding_from(
            &claims(&[
                ("repository", "bank/payments-mcp"),
                ("ref", "refs/heads/main"),
                ("sha", "05e9bde"),
            ]),
            None,
        );
        assert!(matches!(b, SourceBinding::Proven { .. }), "{b:?}");
        assert_eq!(b.sha(), Some("05e9bde"));
    }

    #[test]
    fn gitlab_is_proven_only_on_a_protected_ref() {
        // An unprotected ref means the merge was not gated by review, so the commit is a fact
        // about the token and not evidence of anything. `ref_protected` is a string on the wire.
        let base = [
            ("project_path", "bank/payments-mcp"),
            ("ref", "refs/heads/main"),
            ("sha", "05e9bde"),
        ];
        let mut protected = claims(&base);
        protected.insert("ref_protected".into(), json!("true"));
        assert!(matches!(
            Platform::GitLabCi.binding_from(&protected, None),
            SourceBinding::Proven { .. }
        ));

        let mut unprotected = claims(&base);
        unprotected.insert("ref_protected".into(), json!("false"));
        assert!(matches!(
            Platform::GitLabCi.binding_from(&unprotected, None),
            SourceBinding::Asserted { .. }
        ));
    }

    #[test]
    fn a_weak_platform_cannot_claim_proven_however_confident_the_caller_is() {
        // The property that stops adding Azure DevOps quietly weakening production: an assertion
        // can only ever produce `Asserted`, whatever the caller sends.
        for p in [
            Platform::AzureDevOps,
            Platform::GoogleCloudBuild,
            Platform::BitbucketPipelines,
        ] {
            let b = p.binding_from(&claims(&[("sub", "sc://org/proj/conn")]), Some(&asserted()));
            assert!(
                matches!(b, SourceBinding::Asserted { .. }),
                "{p:?} gave {b:?}"
            );
        }
    }

    #[test]
    fn a_strong_platform_is_not_downgraded_by_an_assertion_either() {
        // The converse, and the reason `asserted` is consulted last: a caller sending its own
        // repo alongside a GitHub token must not be able to replace what the token proved.
        let mut lying = asserted();
        lying.sha = "0000000".into();
        let b = Platform::GitHubActions.binding_from(
            &claims(&[
                ("repository", "bank/payments-mcp"),
                ("ref", "refs/heads/main"),
                ("sha", "05e9bde"),
            ]),
            Some(&lying),
        );
        assert_eq!(
            b.sha(),
            Some("05e9bde"),
            "the token wins over the assertion"
        );
    }

    #[test]
    fn a_policy_floor_refuses_a_weaker_binding_and_accepts_a_stronger_one() {
        let floor = SourceBinding::Verified {
            repo: String::new(),
            git_ref: String::new(),
            sha: String::new(),
        };
        let proven = Platform::GitHubActions.binding_from(
            &claims(&[
                ("repository", "r"),
                ("ref", "refs/heads/main"),
                ("sha", "s"),
            ]),
            None,
        );
        let weak = Platform::AzureDevOps.binding_from(&claims(&[]), Some(&asserted()));
        assert!(proven.meets(&floor), "Proven must satisfy a Verified floor");
        assert!(
            !weak.meets(&floor),
            "Asserted must not satisfy a Verified floor"
        );
        assert!(!SourceBinding::None.meets(&floor));
    }

    #[test]
    fn a_missing_claim_yields_no_binding_rather_than_a_partial_one() {
        // Half a binding is worse than none: a gate reading only `sha` would accept a token
        // that never said which repository it came from.
        let b = Platform::GitHubActions.binding_from(
            &claims(&[("repository", "r"), ("ref", "refs/heads/main")]),
            None,
        );
        assert_eq!(b, SourceBinding::None);

        // And with an assertion present. Found by mutation testing: passing `None` above meant a
        // fallback to the caller's word went unnoticed, which would turn a truncated GitHub
        // token into a fully-trusted binding — the strong platform silently becoming the weak
        // one at exactly the moment its token stopped saying anything.
        let with_assertion = Platform::GitHubActions.binding_from(
            &claims(&[("repository", "r"), ("ref", "refs/heads/main")]),
            Some(&asserted()),
        );
        assert_eq!(
            with_assertion,
            SourceBinding::None,
            "an incomplete token must not be topped up from what the caller claims"
        );
    }

    #[test]
    fn platform_labels_keep_identically_named_subjects_apart() {
        let a = principal_for(Platform::GitHubActions.label(), "repo:bank/x").unwrap();
        let b = principal_for(Platform::AzureDevOps.label(), "repo:bank/x").unwrap();
        assert_ne!(a, b);
        assert!(a.starts_with("urn:wc:ci:gh:"));
    }

    #[test]
    fn a_label_containing_a_colon_is_refused_because_it_makes_the_derivation_ambiguous() {
        assert!(principal_for("gh:extra", "sub").is_err());
        assert!(principal_for("", "sub").is_err());
        assert!(principal_for("gh", "   ").is_err());
    }

    #[test]
    fn registration_is_exact_so_a_similarly_named_repository_inherits_nothing() {
        // The defect this prevents: a glob letting `payments-mcp-test` publish for
        // `payments-mcp`, whose blast radius is every consumer of the real one.
        let asset = EntityId::new("spiffe://bank/ns/svc/sa/payments-mcp").unwrap();
        let mut reg = PipelineRegistry::default();
        reg.allow(
            &asset,
            "urn:wc:ci:gh:repo:bank/payments-mcp:ref:refs/heads/main",
        );

        assert!(reg.may_speak_for(
            "urn:wc:ci:gh:repo:bank/payments-mcp:ref:refs/heads/main",
            &asset
        ));
        for near in [
            "urn:wc:ci:gh:repo:bank/payments-mcp-test:ref:refs/heads/main",
            "urn:wc:ci:gh:repo:bank/payments-mcp",
            "urn:wc:ci:gh:repo:bank/payments-mcp:ref:refs/heads/feature",
            "urn:wc:ci:ado:repo:bank/payments-mcp:ref:refs/heads/main",
            // A strict EXTENSION of the registered principal. Found by mutation testing: the
            // list above all *diverge* from the registered string, so every one of them is
            // refused by prefix matching too — and a `starts_with` implementation passed the
            // whole test. Only a principal that begins with a registered one and continues
            // distinguishes exact matching from prefix matching, and that is the shape an
            // attacker would choose.
            "urn:wc:ci:gh:repo:bank/payments-mcp:ref:refs/heads/main:and-then-some",
        ] {
            assert!(
                !reg.may_speak_for(near, &asset),
                "{near} must not be allowed"
            );
        }
    }

    #[test]
    fn a_shorter_registered_principal_does_not_authorise_longer_ones() {
        // The same gap from the other side: registering a principal with no ref must not
        // authorise every ref under it, which is what prefix matching would do — and would let
        // any branch act for the asset.
        let asset = EntityId::new("spiffe://bank/ns/svc/sa/payments-mcp").unwrap();
        let mut reg = PipelineRegistry::default();
        reg.allow(&asset, "urn:wc:ci:gh:repo:bank/payments-mcp");
        assert!(!reg.may_speak_for(
            "urn:wc:ci:gh:repo:bank/payments-mcp:ref:refs/heads/attacker",
            &asset
        ));
    }

    #[test]
    fn an_unregistered_pipeline_is_refused_with_something_actionable() {
        let asset = EntityId::new("spiffe://bank/ns/svc/sa/payments-mcp").unwrap();
        let reg = PipelineRegistry::default();
        let id = PipelineIdentity {
            principal: "urn:wc:ci:gh:repo:bank/other".into(),
            platform: Platform::GitHubActions,
            binding: SourceBinding::None,
            authority: "https://token.actions.githubusercontent.com".into(),
        };
        let err = reg.authorise(&id, &asset).unwrap_err();
        assert_eq!(err.code(), Code::IDENTITY_UNVERIFIABLE);
        assert!(err.detail().contains("not registered"), "{}", err.detail());
        assert!(err.detail().contains("0 principal"), "{}", err.detail());
    }

    #[test]
    fn a_registry_round_trips_through_toml() {
        let reg = PipelineRegistry::parse(
            r#"
[entries]
"spiffe://bank/ns/svc/sa/payments-mcp" = [
  "urn:wc:ci:gh:repo:bank/payments-mcp:ref:refs/heads/main",
]
"#,
        )
        .unwrap();
        let asset = EntityId::new("spiffe://bank/ns/svc/sa/payments-mcp").unwrap();
        assert!(reg.may_speak_for(
            "urn:wc:ci:gh:repo:bank/payments-mcp:ref:refs/heads/main",
            &asset
        ));
    }

    #[test]
    fn bindings_round_trip_so_they_can_be_recorded_on_a_contract() {
        let b = SourceBinding::Verified {
            repo: "bank/x".into(),
            git_ref: "refs/heads/main".into(),
            sha: "abc".into(),
        };
        let back: SourceBinding =
            serde_json::from_str(&serde_json::to_string(&b).unwrap()).unwrap();
        assert_eq!(b, back);
    }
}
