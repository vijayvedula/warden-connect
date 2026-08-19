//! Asking a source host what was merged, through an operator-supplied shim (W4).
//!
//! Four source hosts are supported — GitHub, GitLab, Azure Repos, Bitbucket — and none of them is
//! integrated in this crate. `signer.rs` set the precedent and the reasoning is identical: four
//! vendor API clients would be four HTTP stacks, four auth models and four pagination schemes
//! inside a crate with a dependency ceiling (§8.3), to answer two questions that a fifteen-line
//! script can answer with the vendor's own CLI. So this defines a protocol and the operator
//! supplies a wrapper. **Adding a fifth host is a script, not a release.**
//!
//! # The protocol
//!
//! ```text
//! stdin   one line of JSON — the query
//! stdout  one line of JSON — the answer. Nothing else
//! stderr  inherited, so diagnostics land in the plane's own log
//! exit    0, or the answer is refused
//! ```
//!
//! Carried over from `signer.rs`, each rule for a reason it learned:
//!
//! * **No shell, argv split on whitespace.** Repository names and paths are attacker-influenceable
//!   strings, and a shim invoked through a shell is an injection surface on the control that
//!   decides whether a contract exists. Anything needing quotes belongs in a script the command
//!   names.
//! * **The query goes on stdin, never argv** — so it appears in no process listing.
//! * **Status before output.** A shim that failed and still printed something must not have that
//!   treated as an answer.
//! * **Empty output on exit 0 is a refusal**, not an empty result.
//! * **A timeout**, because a hung shim otherwise hangs issuance and presents as slowness.
//!
//! # Where the analogy to `signer.rs` breaks, and it matters
//!
//! **A signing shim cannot lie; an SCM shim can.** If a signing wrapper misbehaves, cryptography
//! catches it — `IssuerKey` length-checks the result and names DER specifically. An SCM shim's
//! answer is *just JSON*: one that returns `{"merged":true,"approvers":["someone"]}` mints a
//! contract on fabricated evidence, and nothing downstream can tell.
//!
//! So a shim is a **trusted component**, and the design says so rather than inheriting the
//! signer's comfortable properties by association:
//!
//! * it runs on the control-plane host, deployed by the platform team, with the same trust as the
//!   plane's own configuration. It is never consumer-supplied and never fetched at request time;
//! * [`crate::pipeline::SourceBinding::Verified`] records **which** shim asserted it, so the trust
//!   chain is in the contract rather than implied;
//! * an answer that *contradicts* what the caller asserted is an error, not a weaker binding. A
//!   mismatch means somebody claimed something false, which is a security event and not a reason
//!   to proceed with less confidence.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::json;

use wc_core::error::{Code, Result, WcError};

use crate::pipeline::{Asserted, SourceBinding};

/// How long a shim gets before the answer is refused.
///
/// A source-host API call over the internet is slower than a KMS round trip, so this is looser
/// than `signer.rs`'s ten seconds — and still short enough that a stuck shim is a visible failure
/// rather than a pipeline that appears to hang.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(20);

/// What a source host says about a commit.
///
/// Normalising the vocabulary is most of this module's value. The same concept is a Pull Request,
/// a Merge Request and a Pull Request again; approval is a review state, an approval, and a
/// reviewer vote of at least 10; the branch guard is a protection rule, a protected branch, a
/// branch policy and a branch restriction.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct MergeEvidence {
    /// Whether this commit reached the named ref through a merge.
    pub merged: bool,
    /// The ref it landed on, e.g. `refs/heads/main`.
    #[serde(rename = "ref")]
    pub git_ref: String,
    /// Whether that ref is guarded — protection rule, branch policy, branch restriction.
    pub protected: bool,
    /// The review unit's identifier, as a string: PR/MR numbers are not all integers.
    #[serde(default)]
    pub request_id: String,
    /// Who authored it.
    #[serde(default)]
    pub author: String,
    /// Who approved it.
    #[serde(default)]
    pub approvers: Vec<String>,
    /// When it merged.
    #[serde(default)]
    pub merged_at: u64,
}

impl MergeEvidence {
    /// Whether this is evidence of a *reviewed* merge, and not merely of a merge.
    ///
    /// Three conditions, and dropping any one of them makes the rest decorative:
    /// merged at all, onto a guarded ref, with an approver who is not the author. The last is the
    /// separation-of-duties rule this project keeps — a self-approved merge is one person's
    /// decision wearing two hats.
    #[must_use]
    pub fn is_reviewed_merge(&self) -> bool {
        // A **named** author. An empty one is not "nobody wrote this", it is "the host did not say"
        // — and treating it as nobody makes the third condition vacuous: any approver differs from
        // the empty string, so a self-approved merge would read as reviewed.
        //
        // Found against a live GitHub repository. The wrapper parsed the pull-request JSON with
        // `sed` and a real object carries three `"user":{` occurrences, so greedy matching returned
        // nothing and `author` came back empty. The probe passed, because the merge genuinely had
        // been reviewed by somebody else — the check had stopped checking and the answer was right
        // by luck. The shim is fixed; this is the half that does not depend on the shim being right.
        self.merged
            && self.protected
            && !self.author.trim().is_empty()
            && self
                .approvers
                .iter()
                .any(|a| !a.trim().is_empty() && a.trim() != self.author.trim())
    }

    /// Why it is not evidence, for a refusal an operator can act on.
    #[must_use]
    pub fn why_not_reviewed(&self) -> String {
        if !self.merged {
            return "the commit did not reach that ref through a merge".to_string();
        }
        if self.author.trim().is_empty() {
            return "the host did not name the change's author, so \"an approver who is not the \
                    author\" cannot be checked at all. An unnamed author is unknown, not nobody — \
                    probe the shim with `connect scm probe` and confirm it reports one"
                .to_string();
        }
        if !self.protected {
            return format!(
                "{} is not a guarded ref, so a merge onto it is not evidence of review",
                self.git_ref
            );
        }
        if self.approvers.is_empty() {
            return "the merge carries no approver".to_string();
        }
        format!(
            "the only approver is the author ({}), and a self-approved merge is one person's \
             decision wearing two hats",
            self.author
        )
    }
}

/// A source-host shim: a command that answers the protocol above.
#[derive(Debug, Clone)]
pub struct ScmShim {
    program: PathBuf,
    args: Vec<String>,
    timeout: Duration,
    /// A short operator-chosen name, recorded on the binding so the trust chain is visible.
    label: String,
}

impl ScmShim {
    /// Build a shim from a label and a command line.
    ///
    /// Whitespace-split, no shell — see the module note. A label is required because a
    /// `Verified` binding is only as good as the shim that produced it, and a contract that did
    /// not say which one would be recording trust without naming its source.
    pub fn parse(label: &str, command: &str) -> Result<ScmShim> {
        if label.trim().is_empty() {
            return Err(WcError::with_detail(
                Code::CONFIG_INVALID,
                "an scm shim needs a label; a Verified binding records which shim vouched for it",
            ));
        }
        let mut parts = command.split_whitespace();
        let program = parts.next().ok_or_else(|| {
            WcError::with_detail(Code::CONFIG_INVALID, "scm shim command is empty")
        })?;
        Ok(ScmShim {
            program: PathBuf::from(program),
            args: parts.map(str::to_string).collect(),
            timeout: DEFAULT_TIMEOUT,
            label: label.trim().to_string(),
        })
    }

    /// Override the timeout.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> ScmShim {
        self.timeout = timeout;
        self
    }

    /// The operator-chosen name of this shim.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    /// A failure on the write op.
    ///
    /// `Code::IDENTITY_UNVERIFIABLE` is right for the read ops — a shim that cannot answer about a
    /// merge has left a binding unverifiable. It is wrong here and actively misleading: opening a
    /// pull request is not an identity question, and a mistyped repository name reported as
    /// *workload identity unverifiable* sends an operator to look at SPIFFE and tokens. Seen exactly
    /// that way in a live run, where the real cause was a placeholder left in a command.
    fn fail_write(&self, detail: impl std::fmt::Display) -> WcError {
        WcError::with_detail(
            Code::EXPORT_FAILED,
            format!("{} could not open the pull request: {detail}", self.label()),
        )
    }

    /// The shim could not be run at all — a configuration error, not an identity verdict.
    ///
    /// `fail` reports `WC-1001 workload identity unverifiable`, which is right when the host was
    /// asked and its answer did not establish consent. It is wrong, and actively misleading, when
    /// the shim never ran: a mistyped path exits 127, and "workload identity unverifiable" sends an
    /// operator to look at attestation instead of at the flag they got wrong. Seen live — a `~` in a
    /// quoted shell variable, reported as an identity problem.
    fn misconfigured(&self, detail: impl std::fmt::Display) -> WcError {
        WcError::with_detail(
            Code::CONFIG_INVALID,
            format!(
                "scm shim {}: {detail}. Nothing was asked of the source host, so this says nothing \
                 about the commit — fix the shim command and re-run",
                self.program.display()
            ),
        )
    }

    fn fail(&self, detail: impl std::fmt::Display) -> WcError {
        WcError::with_detail(
            Code::IDENTITY_UNVERIFIABLE,
            format!("scm shim {}: {detail}", self.program.display()),
        )
    }

    /// Ask the shim one question and parse its answer.
    fn ask(&self, query: &serde_json::Value) -> Result<serde_json::Value> {
        let mut child = Command::new(&self.program)
            .args(&self.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| {
                self.misconfigured("cannot be started (is the path right, and executable?)")
                    .with_source(e)
            })?;

        {
            let Some(mut stdin) = child.stdin.take() else {
                kill(&mut child);
                return Err(self.fail("no stdin on the shim"));
            };
            // Dropped at the end of this block, closing the pipe. A shim reading to EOF would
            // otherwise wait for input that never ends.
            let line = query.to_string();
            if let Err(e) = stdin
                .write_all(line.as_bytes())
                .and_then(|()| stdin.write_all(b"\n"))
            {
                drop(stdin);
                kill(&mut child);
                return Err(self.fail("cannot write the query").with_source(e));
            }
        }

        let Some(mut stdout) = child.stdout.take() else {
            kill(&mut child);
            return Err(self.fail("no stdout on the shim"));
        };
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut buf = String::new();
            let read = stdout.read_to_string(&mut buf);
            let _ = tx.send(read.map(|_| buf));
        });

        let out = match rx.recv_timeout(self.timeout) {
            Ok(Ok(text)) => text,
            Ok(Err(e)) => {
                kill(&mut child);
                return Err(self.fail("cannot read the answer").with_source(e));
            }
            Err(_) => {
                kill(&mut child);
                return Err(self.fail(format!("no answer within {:?}", self.timeout)));
            }
        };

        let status = child
            .wait()
            .map_err(|e| self.fail("cannot reap").with_source(e))?;
        if !status.success() {
            // 127 is "command not found" and 126 is "found but not executable". Both mean the shim
            // never ran, so neither is an answer about the commit — reported as configuration.
            // Every other non-zero exit is the shim itself refusing, which is a real verdict.
            if matches!(status.code(), Some(126 | 127)) {
                return Err(self.misconfigured(format!(
                    "exited {status}, which means the command was not found or is not executable"
                )));
            }
            // Status before output: a shim that failed and still printed something must not have
            // that treated as an answer.
            return Err(self.fail(format!("exited {status}")));
        }
        let trimmed = out.trim();
        if trimmed.is_empty() {
            return Err(self.fail("exited 0 and produced no answer"));
        }
        serde_json::from_str(trimmed)
            .map_err(|e| self.fail("answer is not one line of JSON").with_source(e))
    }

    /// What the host says about a commit on a repository.
    ///
    /// `repo` is passed through **opaquely and never parsed**: Azure Repos is
    /// `org/project/repo`, GitLab nests arbitrarily and Bitbucket addresses by UUID. Anything
    /// here that assumed a two-part path would break on three of the four supported hosts.
    pub fn merge_evidence(&self, repo: &str, sha: &str) -> Result<MergeEvidence> {
        let answer = self.ask(&json!({ "op": "merge_evidence", "repo": repo, "sha": sha }))?;
        serde_json::from_value(answer)
            .map_err(|e| self.fail("answer is not merge evidence").with_source(e))
    }

    /// A file's bytes at a commit.
    ///
    /// A shim may answer `{"absent": true}` for a path that simply is not there. That is a
    /// different answer from a failure, and keeping them apart is what lets a scan report an empty
    /// estate honestly instead of reporting one for an expired token.
    pub fn file(&self, repo: &str, sha: &str, path: &str) -> Result<Vec<u8>> {
        let answer = self.ask(&json!({ "op": "file", "repo": repo, "sha": sha, "path": path }))?;
        if answer
            .get("absent")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
        {
            return Err(self.fail(format!("{path} is not present in {repo} at {sha}")));
        }
        let b64 = answer
            .get("content_b64")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| self.fail("answer carries no `content_b64`"))?;
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|e| {
                self.fail("`content_b64` is not standard base64")
                    .with_source(e)
            })
    }
}

/// A file to place on a branch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PrFile {
    /// Path in the repository.
    pub path: String,
    /// Contents, standard base64.
    pub content_b64: String,
}

impl PrFile {
    /// A file from its path and its bytes.
    ///
    /// The base64 lives here rather than at the call site because the encoding is this protocol's
    /// business — and because a caller that had to do it would need a base64 dependency of its own
    /// for one line, which §8.3's ceilings exist to prevent.
    #[must_use]
    pub fn new(path: impl Into<String>, bytes: &[u8]) -> PrFile {
        use base64::Engine as _;
        PrFile {
            path: path.into(),
            content_b64: base64::engine::general_purpose::STANDARD.encode(bytes),
        }
    }
}

/// A pull request to open.
///
/// `branch` is **derived from the content by the caller**, not generated randomly, and that is what
/// makes raising the same proposal twice idempotent. A portal button clicked twice, or a scan run
/// nightly, must not leave a queue of duplicate pull requests for one decision — a reviewer facing
/// forty identical PRs stops reading all of them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PrRequest {
    /// Opaque repository id — the one contracts repository.
    pub repo: String,
    /// Branch to merge into.
    pub base: String,
    /// Branch to create, derived from the content.
    pub branch: String,
    /// Pull request title.
    pub title: String,
    /// Pull request body.
    pub body: String,
    /// Files to place on the branch.
    pub files: Vec<PrFile>,
}

/// What opening a pull request produced.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct PrOutcome {
    /// The review unit's id, as a string.
    #[serde(default)]
    pub request_id: String,
    /// A link a human can open.
    #[serde(default)]
    pub url: String,
    /// Whether this call created it, or found one already open for the same branch.
    #[serde(default)]
    pub created: bool,
}

impl ScmShim {
    /// Open a pull request carrying these files.
    ///
    /// **The only write this system performs against a source host, and it is deliberately the
    /// weakest one available.** There is no merge op and there never should be: the whole value of
    /// this arrangement is that a human merges, in a tool they already use, and a system that could
    /// merge its own proposals would be approving on their behalf.
    ///
    /// So the token this shim carries needs `contents:write` and `pull-requests:write` on **one**
    /// repository, and must not be able to merge. Branch protection requiring a review is what
    /// enforces that, and it is the same protection `merge_evidence` later reads back — so an estate
    /// that has not set it will find `proposals apply` refusing the merge it produced.
    pub fn open_pr(&self, request: &PrRequest) -> Result<PrOutcome> {
        let mut payload = serde_json::to_value(request)
            .map_err(|e| self.fail_write("cannot encode it").with_source(e))?;
        if let Some(obj) = payload.as_object_mut() {
            obj.insert("op".to_string(), json!("open_pr"));
        }
        // Mapped rather than propagated, so the shim's own stderr survives while the code stops
        // claiming an identity problem. The detail is what an operator reads; the code is what they
        // route on.
        let answer = self
            .ask(&payload)
            .map_err(|e| self.fail_write(e.detail().to_string()))?;
        let outcome: PrOutcome = serde_json::from_value(answer).map_err(|e| {
            self.fail_write("the answer is not an outcome")
                .with_source(e)
        })?;
        if outcome.request_id.trim().is_empty() {
            // A shim that opened a pull request and could not say which one has produced something
            // nobody can find, review or merge. Refused rather than reported as success, because
            // the caller is about to tell an operator to go and get it approved.
            return Err(self.fail(
                "the answer names no pull request, so nothing can be reviewed or merged. A write \
                 that cannot be pointed at is not a write worth reporting",
            ));
        }
        Ok(outcome)
    }

    /// Every repository the shim can see, for a whole organisation.
    ///
    /// The inventory's entry point. Deliberately a *list of opaque ids* and nothing else: what a
    /// repository is called differs per host, and the inventory only ever passes these straight
    /// back to [`ScmShim::file`].
    ///
    /// A host that cannot enumerate — a token scoped to one repository, a shim that declines — says
    /// so by returning an empty list, and the caller reports "nothing to scan" rather than "nothing
    /// found". Those are different answers and an inventory that conflates them is an inventory
    /// that reports a clean estate for a permissions problem.
    pub fn repos(&self, org: &str) -> Result<Vec<String>> {
        let answer = self.ask(&json!({ "op": "repos", "org": org }))?;
        let list = answer
            .get("repos")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| self.fail("answer carries no `repos` array"))?;
        Ok(list
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect())
    }

    /// A file at a revision, or `None` when the host says it is not there.
    ///
    /// **Absence only.** Any other failure propagates, and that distinction is the whole point: an
    /// earlier version swallowed every error, so a scan with an expired token, a broken shim or a
    /// rate limit would have reported an estate with no MCP servers in it. "I looked and found
    /// nothing" and "I could not look" must never render the same, and this is the layer where they
    /// would have been merged.
    pub fn file_if_present(&self, repo: &str, sha: &str, path: &str) -> Result<Option<Vec<u8>>> {
        let answer = self.ask(&json!({ "op": "file", "repo": repo, "sha": sha, "path": path }))?;
        if answer
            .get("absent")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
        {
            return Ok(None);
        }
        let b64 = answer
            .get("content_b64")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| self.fail("answer carries neither `content_b64` nor `absent`"))?;
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map(Some)
            .map_err(|e| {
                self.fail("`content_b64` is not standard base64")
                    .with_source(e)
            })
    }
}

/// Kill a child and reap it, so a timed-out shim is not left behind.
fn kill(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// Raise an asserted binding to [`SourceBinding::Verified`] by asking the source host.
///
/// This is what makes the three platforms whose tokens cannot prove a commit — Azure DevOps, AWS
/// CodeBuild, Google Cloud Build — usable at the same bar as GitHub and GitLab. Trust moves from
/// the CI platform to the source host, which is where it belongs: the pipeline cannot lie about
/// the commit, because somebody looked.
///
/// A **contradiction is an error, not a downgrade.** If the caller asserted a ref the host
/// disagrees with, that is somebody claiming something false; returning a weaker binding would
/// let them proceed with a lie priced in.
pub fn verify_binding(shim: &ScmShim, asserted: &Asserted) -> Result<SourceBinding> {
    checked_evidence(shim, asserted)?;
    Ok(SourceBinding::Verified {
        repo: asserted.repo.clone(),
        git_ref: asserted.git_ref.clone(),
        sha: asserted.sha.clone(),
    })
}

/// Ask the host, and refuse anything that is not a reviewed merge of what was asserted.
///
/// Shared by [`verify_binding`] and [`crate::authority::ScmMerge`], which want the same three
/// conditions checked and two different things built from the answer. Two copies of "is this a
/// reviewed merge" is the shape of defect this project keeps finding — one of them ends up
/// missing a condition, and the one that matters is whichever the caller happens to use.
pub fn checked_evidence(shim: &ScmShim, asserted: &Asserted) -> Result<MergeEvidence> {
    let evidence = shim.merge_evidence(&asserted.repo, &asserted.sha)?;

    if evidence.git_ref != asserted.git_ref {
        return Err(WcError::with_detail(
            Code::IDENTITY_UNVERIFIABLE,
            format!(
                "the pipeline asserted {} but {} reports {sha} merged onto {}; a disagreement \
                 about which ref a commit landed on is not a weaker claim, it is a false one",
                asserted.git_ref,
                shim.label(),
                evidence.git_ref,
                sha = asserted.sha,
            ),
        ));
    }
    if !evidence.is_reviewed_merge() {
        return Err(WcError::with_detail(
            Code::IDENTITY_UNVERIFIABLE,
            format!(
                "{} is not evidence of a reviewed merge: {}",
                asserted.sha,
                evidence.why_not_reviewed()
            ),
        ));
    }
    Ok(evidence)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    /// A scratch directory for shim scripts. Cleared before use, because `create_dir_all` keeps
    /// the contents of an existing path and these names repeat across runs.
    struct Dir(PathBuf);

    impl Dir {
        fn new(tag: &str) -> Dir {
            use std::sync::atomic::{AtomicU32, Ordering};
            static N: AtomicU32 = AtomicU32::new(0);
            let n = N.fetch_add(1, Ordering::SeqCst);
            let p = std::env::temp_dir().join(format!("wc-scm-{}-{tag}-{n}", std::process::id()));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).unwrap();
            Dir(p)
        }
        fn shim(&self, body: &str) -> String {
            use std::os::unix::fs::PermissionsExt;
            let path = self.0.join("shim.sh");
            std::fs::write(&path, body).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            format!("/bin/sh {}", path.display())
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn answering(tag: &str, json_line: &str) -> (Dir, ScmShim) {
        let d = Dir::new(tag);
        let cmd = d.shim(&format!("cat > /dev/null\nprintf '%s\\n' '{json_line}'\n"));
        let shim = ScmShim::parse("test", &cmd)
            .unwrap()
            .with_timeout(Duration::from_secs(5));
        (d, shim)
    }

    fn asserted() -> Asserted {
        Asserted {
            repo: "bank/payments-mcp".into(),
            git_ref: "refs/heads/main".into(),
            sha: "05e9bde".into(),
        }
    }

    #[test]
    fn a_shim_that_cannot_run_is_a_config_error_not_an_identity_verdict() {
        // The distinction an operator acts on. A mistyped path used to report `WC-1001 workload
        // identity unverifiable`, which reads as "the host said no" and sends them to attestation.
        // Nothing was asked of the host at all.
        let shim = ScmShim::parse("gh", "/nonexistent/definitely-not-here.sh").unwrap();
        let err = shim
            .merge_evidence("acme/repo", "deadbeef")
            .expect_err("a missing shim cannot answer");
        assert_eq!(
            err.code(),
            Code::CONFIG_INVALID,
            "a shim that never ran must not produce an identity verdict: {err}"
        );
        assert!(
            err.detail().contains("says nothing about the commit"),
            "the message must say the host was never asked: {}",
            err.detail()
        );
    }

    #[test]
    fn a_shim_that_spawns_and_exits_127_is_also_a_config_error() {
        // The case that actually happened. `bash ~/path/to/shim.sh` with a tilde inside quotes:
        // bash starts perfectly, cannot find the file, exits 127. The spawn succeeded, so the test
        // above does not cover this at all — it fails at spawn and never reaches the exit check.
        // Confirmed by mutation: with the 126/127 branch forced false, that test still passed.
        let d = Dir::new("notfound");
        let shim = ScmShim::parse("gh", &d.shim("exit 127\n")).unwrap();
        let err = shim
            .merge_evidence("acme/repo", "deadbeef")
            .expect_err("127 means the command was never found");
        assert_eq!(err.code(), Code::CONFIG_INVALID, "{err}");
    }

    #[test]
    fn a_shim_that_runs_and_refuses_is_still_an_identity_verdict() {
        // The other half, or the fix above would swallow real refusals. A deliberate non-zero exit
        // that is not 126/127 is the shim itself saying no, which is a verdict about the commit.
        //
        // Written as a script rather than `sh -c 'exit 1'`: `ScmShim::parse` splits on whitespace,
        // so the quoted form arrives as two mangled arguments and exits with a shell syntax error
        // instead of the code intended. It passed, for the wrong reason.
        let d = Dir::new("refuses");
        let shim = ScmShim::parse("gh", &d.shim("exit 1\n")).unwrap();
        let err = shim
            .merge_evidence("acme/repo", "deadbeef")
            .expect_err("exit 1 is a refusal");
        assert_eq!(err.code(), Code::IDENTITY_UNVERIFIABLE, "{err}");
    }

    const GOOD: &str = r#"{"merged":true,"ref":"refs/heads/main","protected":true,"request_id":"214","author":"r.mehta","approvers":["s.iyer"],"merged_at":1786449873}"#;

    #[test]
    fn a_reviewed_merge_raises_an_asserted_binding_to_verified() {
        let (_d, shim) = answering("good", GOOD);
        let b = verify_binding(&shim, &asserted()).unwrap();
        assert!(matches!(b, SourceBinding::Verified { .. }), "{b:?}");
        assert!(
            b.strength()
                > SourceBinding::Asserted {
                    repo: String::new(),
                    git_ref: String::new(),
                    sha: String::new()
                }
                .strength()
        );
    }

    #[test]
    fn a_ref_the_host_disagrees_with_is_an_error_not_a_downgrade() {
        // The caller said main; the host says a feature branch. Returning `Asserted` here would
        // let somebody proceed with a lie priced in.
        let (_d, shim) = answering(
            "wrongref",
            r#"{"merged":true,"ref":"refs/heads/feature","protected":true,"author":"a","approvers":["b"]}"#,
        );
        let err = verify_binding(&shim, &asserted()).unwrap_err();
        assert!(err.detail().contains("false one"), "{}", err.detail());
    }

    #[test]
    fn an_unmerged_commit_is_refused() {
        let (_d, shim) = answering(
            "unmerged",
            r#"{"merged":false,"ref":"refs/heads/main","protected":true,"author":"a","approvers":["b"]}"#,
        );
        let err = verify_binding(&shim, &asserted()).unwrap_err();
        assert!(err.detail().contains("through a merge"), "{}", err.detail());
    }

    #[test]
    fn a_merge_onto_an_unguarded_ref_is_not_evidence_of_review() {
        // Without branch protection nothing forced a review, so the merge proves only that
        // somebody could push.
        let (_d, shim) = answering(
            "unprotected",
            r#"{"merged":true,"ref":"refs/heads/main","protected":false,"author":"a","approvers":["b"]}"#,
        );
        let err = verify_binding(&shim, &asserted()).unwrap_err();
        assert!(
            err.detail().contains("not a guarded ref"),
            "{}",
            err.detail()
        );
    }

    #[test]
    fn a_self_approved_merge_is_refused() {
        // The one separation-of-duties rule this design keeps: requester is not approver.
        let (_d, shim) = answering(
            "selfapproved",
            r#"{"merged":true,"ref":"refs/heads/main","protected":true,"author":"a.khan","approvers":["a.khan"]}"#,
        );
        let err = verify_binding(&shim, &asserted()).unwrap_err();
        assert!(err.detail().contains("two hats"), "{}", err.detail());
    }

    #[test]
    fn a_merge_whose_author_the_host_did_not_name_is_refused() {
        // Found against a live GitHub repository, and it is the reason this test exists rather than
        // the reason it was added afterwards. The wrapper parsed pull-request JSON with `sed`; a
        // real object carries three `"user":{` occurrences, greedy matching took the last, and
        // `author` came back empty.
        //
        // An empty author is not "nobody wrote this", it is "the host did not say" — and treating it
        // as nobody makes the separation-of-duties rule vacuous, because every approver differs from
        // the empty string. A self-approved merge would then read as reviewed. The probe passed at
        // the time only because that particular merge genuinely had been reviewed by someone else:
        // the check had stopped checking and the answer was right by luck.
        let (_d, shim) = answering(
            "noauthor",
            r#"{"merged":true,"ref":"refs/heads/main","protected":true,"author":"","approvers":["b.singh"]}"#,
        );
        let err = verify_binding(&shim, &asserted()).unwrap_err();
        assert!(
            err.detail().contains("did not name"),
            "the refusal must say the host named no author: {}",
            err.detail()
        );

        // Whitespace counts as unnamed. A host that answers `" "` has said nothing either, and a
        // check defeated by a space is a check defeated.
        let (_d2, shim2) = answering(
            "blankauthor",
            r#"{"merged":true,"ref":"refs/heads/main","protected":true,"author":"  ","approvers":["b.singh"]}"#,
        );
        assert!(verify_binding(&shim2, &asserted()).is_err());
    }

    #[test]
    fn an_approver_differing_from_the_author_only_by_whitespace_is_not_a_second_person() {
        // `" a.khan"` and `"a.khan"` are one person however a host spells them, and trimming on one
        // side only would let padding buy a second signature.
        let (_d, shim) = answering(
            "paddedself",
            r#"{"merged":true,"ref":"refs/heads/main","protected":true,"author":"a.khan","approvers":[" a.khan "]}"#,
        );
        assert!(verify_binding(&shim, &asserted()).is_err());
    }

    #[test]
    fn a_merge_with_no_approver_is_refused() {
        let (_d, shim) = answering(
            "noapprover",
            r#"{"merged":true,"ref":"refs/heads/main","protected":true,"author":"a","approvers":[]}"#,
        );
        let err = verify_binding(&shim, &asserted()).unwrap_err();
        assert!(err.detail().contains("no approver"), "{}", err.detail());
    }

    #[test]
    fn a_shim_that_exits_non_zero_answers_nothing_even_if_it_printed() {
        // Status before output. A shim that failed and still printed must not have that treated
        // as an answer — the same rule `signer.rs` learned about signatures.
        let d = Dir::new("angry");
        let cmd = d.shim(&format!(
            "cat > /dev/null\nprintf '%s\\n' '{GOOD}'\nexit 3\n"
        ));
        let shim = ScmShim::parse("test", &cmd).unwrap();
        let err = verify_binding(&shim, &asserted()).unwrap_err();
        assert!(err.detail().contains("exited"), "{}", err.detail());
    }

    #[test]
    fn a_shim_that_exits_zero_and_says_nothing_is_a_refusal_not_an_empty_result() {
        let d = Dir::new("quiet");
        let cmd = d.shim("cat > /dev/null\nexit 0\n");
        let shim = ScmShim::parse("test", &cmd).unwrap();
        let err = verify_binding(&shim, &asserted()).unwrap_err();
        assert!(err.detail().contains("no answer"), "{}", err.detail());
    }

    #[test]
    fn a_hanging_shim_times_out_rather_than_hanging_issuance() {
        let d = Dir::new("hang");
        let cmd = d.shim("cat > /dev/null\nsleep 30\n");
        let shim = ScmShim::parse("test", &cmd)
            .unwrap()
            .with_timeout(Duration::from_millis(400));
        let err = verify_binding(&shim, &asserted()).unwrap_err();
        assert!(
            err.detail().contains("no answer within"),
            "{}",
            err.detail()
        );
    }

    #[test]
    fn garbage_from_a_shim_is_an_error_not_a_panic() {
        let (_d, shim) = answering("garbage", "not json at all");
        let err = verify_binding(&shim, &asserted()).unwrap_err();
        assert!(
            err.detail().contains("not one line of JSON"),
            "{}",
            err.detail()
        );
    }

    #[test]
    fn an_answer_missing_a_required_field_is_refused_rather_than_defaulted() {
        // `merged` and `protected` have no serde default on purpose: defaulting either to
        // `false` would turn a malformed answer into a clean refusal, and defaulting to `true`
        // would be catastrophic. Absent means the shim did not answer the question.
        let (_d, shim) = answering("partial", r#"{"ref":"refs/heads/main","protected":true}"#);
        let err = verify_binding(&shim, &asserted()).unwrap_err();
        assert!(
            err.detail().contains("not merge evidence"),
            "{}",
            err.detail()
        );
    }

    #[test]
    fn a_file_is_returned_from_standard_base64() {
        // Standard base64, not base64url. The attestation drill's first run died on exactly
        // that confusion in a DSSE envelope, so the alphabet is named in the protocol.
        let (_d, shim) = answering("file", r#"{"content_b64":"aGVsbG8gd29ybGQ="}"#);
        let bytes = shim.file("bank/x", "05e9bde", "warden/offer.toml").unwrap();
        assert_eq!(bytes, b"hello world");
    }

    #[test]
    fn a_shim_needs_a_label_so_a_verified_binding_names_its_source() {
        assert!(ScmShim::parse("", "/bin/true").is_err());
        assert!(ScmShim::parse("gh", "   ").is_err());
    }

    #[test]
    fn the_query_reaches_the_shim_on_stdin_and_not_in_argv() {
        // argv is visible in a process listing. A repository name is not a secret, but the
        // discipline is the one `signer.rs` keeps and it costs nothing.
        //
        // The shim records what it read to a file rather than echoing it back through JSON: the
        // first version of this test built the answer with nested shell quoting and failed on
        // its own escaping, which proved nothing about the product.
        let d = Dir::new("stdin");
        let seen = d.0.join("seen.txt");
        let cmd = d.shim(&format!(
            "cat > {}\nprintf '%s\\n' '{GOOD}'\n",
            seen.display()
        ));
        let shim = ScmShim::parse("test", &cmd).unwrap();
        shim.merge_evidence("bank/payments-mcp", "05e9bde").unwrap();

        let captured = std::fs::read_to_string(&seen).expect("the shim wrote what it read");
        let query: serde_json::Value = serde_json::from_str(captured.trim()).unwrap();
        assert_eq!(query["op"], "merge_evidence");
        assert_eq!(query["repo"], "bank/payments-mcp");
        assert_eq!(query["sha"], "05e9bde");
    }

    #[test]
    fn an_opaque_repo_identifier_passes_through_unparsed() {
        // Azure Repos is org/project/repo, GitLab nests arbitrarily, Bitbucket uses a UUID.
        // Anything that split or normalised this would break on three of the four hosts.
        let d = Dir::new("opaque");
        let seen = d.0.join("seen.txt");
        let cmd = d.shim(&format!(
            "cat > {}\nprintf '%s\\n' '{GOOD}'\n",
            seen.display()
        ));
        let shim = ScmShim::parse("test", &cmd).unwrap();
        for weird in [
            "bank/platform/payments-mcp",
            "group/sub/sub2/project",
            "{11111111-2222-3333-4444-555555555555}",
        ] {
            shim.merge_evidence(weird, "05e9bde").unwrap();
            let q: serde_json::Value =
                serde_json::from_str(std::fs::read_to_string(&seen).unwrap().trim()).unwrap();
            assert_eq!(q["repo"], weird, "the identifier must arrive unchanged");
        }
    }
}
