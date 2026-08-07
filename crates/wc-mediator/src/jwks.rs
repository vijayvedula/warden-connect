//! Issuer keys pulled from a published key set, so rotation stops being a deployment
//! (`docs/production-readiness.md` P0 #6).
//!
//! Before this, a mediator's trust was `--issuer-pub` — one PEM, fixed at startup.
//! Rotating the issuer key meant copying a file to every mediator and restarting each
//! one, which is why in practice keys do not get rotated: the procedure costs an
//! availability risk, so it is deferred, so the key stays live for years. Pointing a
//! mediator at the issuer's `jwks.json` moves rotation to publishing a document.
//!
//! # Replace, not merge
//!
//! [`IssuerKeys::add_jwks`] is additive, which is right for an operator assembling
//! trust out of several files. A *source* is not additive. The document is the issuer's
//! current answer to "which keys are mine", and a key that has left it has left it —
//! usually because it was compromised, which is the case that matters. A cache that
//! merged each fetch into the last would keep honouring a withdrawn key forever, and
//! would do it while reporting healthy refreshes. So every refresh builds a fresh
//! [`IssuerKeys`] and swaps it in whole.
//!
//! # What happens when the fetch fails
//!
//! The keys already held are still cryptographically valid; the issuer being briefly
//! unreachable says nothing about them. Dropping them would convert "the key server had
//! a bad minute" into "every connection is refused", so a failed refresh keeps serving
//! the cached set — but only up to [`JwksSource::with_max_stale`]. Past that the source
//! refuses, because at some distance the cache has stopped being a cache and become a
//! way of not noticing that revocation cannot reach this process any more.
//!
//! Both halves are visible: [`JwksSource::status`] reports age, staleness and the last
//! error, so "serving from cache because the issuer is down" is something an operator
//! can alert on rather than something they infer afterwards.

use std::path::PathBuf;
use std::time::Duration;

use wc_core::contract::{IssuerKeys, JwksReport};
use wc_core::error::{Code, Result, WcError};

/// Where a key set comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Origin {
    /// An HTTPS URL, re-fetched on the TTL.
    Url(String),
    /// A file on disk — a SPIRE bundle written by `spire-agent api fetch jwtbundles`,
    /// or a ConfigMap mount. Re-read on the same TTL, because a mounted file changes
    /// under a running process without the process being told.
    File(PathBuf),
}

impl Origin {
    /// How this origin names itself in an error or a status line.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Origin::Url(u) => u.clone(),
            Origin::File(p) => p.display().to_string(),
        }
    }
}

/// What the source is currently doing, for a status endpoint or a log line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    /// Where the keys came from.
    pub origin: String,
    /// Key ids currently trusted.
    pub kids: Vec<String>,
    /// Seconds since the last **successful** load. `None` before the first one.
    pub age: Option<u64>,
    /// Whether the set is past its TTL and being served anyway.
    pub stale: bool,
    /// Whether it is past `max_stale` and therefore no longer served at all.
    pub expired: bool,
    /// Why the last refresh failed, if it did. Cleared by a success.
    pub last_error: Option<String>,
}

/// A key set with a TTL, refreshed from its origin.
#[derive(Debug)]
pub struct JwksSource {
    origin: Origin,
    ttl: u64,
    max_stale: u64,
    timeout: Duration,
    keys: Option<IssuerKeys>,
    loaded_at: u64,
    last_error: Option<String>,
}

impl JwksSource {
    /// Default TTL. Short enough that a rotation propagates inside a coffee break,
    /// long enough that a fleet of mediators is not a load generator.
    pub const DEFAULT_TTL: u64 = 300;

    /// Default staleness bound: one hour. Past this the cached set stops being served.
    ///
    /// The number is a judgement, and the judgement is that an hour of key-server
    /// outage is an incident somebody is already awake for, while a day of it is a
    /// mediator quietly running on keys nobody can withdraw.
    pub const DEFAULT_MAX_STALE: u64 = 3_600;

    /// A source over HTTP(S).
    #[must_use]
    pub fn url(url: &str) -> JwksSource {
        JwksSource::new(Origin::Url(url.to_string()))
    }

    /// A source backed by a file.
    #[must_use]
    pub fn file(path: impl Into<PathBuf>) -> JwksSource {
        JwksSource::new(Origin::File(path.into()))
    }

    fn new(origin: Origin) -> JwksSource {
        JwksSource {
            origin,
            ttl: JwksSource::DEFAULT_TTL,
            max_stale: JwksSource::DEFAULT_MAX_STALE,
            timeout: Duration::from_secs(10),
            keys: None,
            loaded_at: 0,
            last_error: None,
        }
    }

    /// How long a loaded set is considered fresh.
    #[must_use]
    pub fn with_ttl(mut self, seconds: u64) -> JwksSource {
        self.ttl = seconds;
        self
    }

    /// How far past the TTL a cached set may still be served when refresh is failing.
    ///
    /// Setting this below the TTL means a single failed refresh takes the source out,
    /// so it is clamped up: a configuration that made the cache useless would present
    /// as a tightening and behave as an outage.
    #[must_use]
    pub fn with_max_stale(mut self, seconds: u64) -> JwksSource {
        self.max_stale = seconds.max(self.ttl);
        self
    }

    /// Request timeout for a URL origin.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> JwksSource {
        self.timeout = timeout;
        self
    }

    /// Where this source reads from.
    #[must_use]
    pub fn origin(&self) -> &Origin {
        &self.origin
    }

    /// Load now, regardless of the TTL. Returns what the document yielded.
    ///
    /// On failure the previously loaded set is left in place and the error is recorded;
    /// the caller gets the error too, so a startup load can fail loudly while a
    /// periodic one can be logged and retried.
    pub fn load(&mut self, now: u64) -> Result<JwksReport> {
        let document = match self.read() {
            Ok(d) => d,
            Err(e) => {
                self.last_error = Some(format!("{e}"));
                return Err(e);
            }
        };

        // Into a fresh set: see the module note on replace-not-merge. A withdrawn key
        // has to actually stop verifying.
        let mut fresh = IssuerKeys::default();
        match fresh.add_jwks(&document) {
            Ok(report) => {
                self.keys = Some(fresh);
                self.loaded_at = now;
                self.last_error = None;
                Ok(report)
            }
            Err(e) => {
                self.last_error = Some(format!("{e}"));
                Err(e)
            }
        }
    }

    /// Load only if the current set is past its TTL. Returns `Some` if it loaded.
    ///
    /// Called on the mediator's refresh tick beside the contract pull, so key rotation
    /// rides the loop that already exists rather than needing a thread of its own.
    pub fn refresh(&mut self, now: u64) -> Result<Option<JwksReport>> {
        if self.keys.is_some() && !self.past_ttl(now) {
            return Ok(None);
        }
        self.load(now).map(Some)
    }

    /// The keys, if they may still be trusted.
    ///
    /// Refuses once nothing has loaded, or once the cached set is past `max_stale` —
    /// the two cases where returning an empty or ancient set would let verification
    /// proceed on a trust set that is not the issuer's.
    pub fn keys(&self, now: u64) -> Result<&IssuerKeys> {
        let Some(keys) = self.keys.as_ref() else {
            return Err(WcError::with_detail(
                Code::CONFIG_INVALID,
                format!(
                    "no issuer keys loaded from {}{}",
                    self.origin.describe(),
                    match &self.last_error {
                        Some(e) => format!(": {e}"),
                        None => String::new(),
                    }
                ),
            ));
        };
        if self.expired(now) {
            return Err(WcError::with_detail(
                Code::CONFIG_INVALID,
                format!(
                    "issuer keys from {} are {}s old, past the {}s staleness bound; a \
                     withdrawn key could still be trusted, so verification stops here{}",
                    self.origin.describe(),
                    self.age(now).unwrap_or(0),
                    self.max_stale,
                    match &self.last_error {
                        Some(e) => format!(" (last refresh: {e})"),
                        None => String::new(),
                    }
                ),
            ));
        }
        Ok(keys)
    }

    /// Seconds since the last successful load.
    #[must_use]
    pub fn age(&self, now: u64) -> Option<u64> {
        self.keys
            .as_ref()
            .map(|_| now.saturating_sub(self.loaded_at))
    }

    /// Whether the set is past its TTL. Clock skew backwards reads as fresh rather
    /// than as an enormous age, so a corrected clock does not expire a good set.
    #[must_use]
    pub fn past_ttl(&self, now: u64) -> bool {
        self.age(now).is_some_and(|a| a >= self.ttl)
    }

    /// Whether the set is past `max_stale` and no longer served.
    #[must_use]
    pub fn expired(&self, now: u64) -> bool {
        self.age(now).is_some_and(|a| a > self.max_stale)
    }

    /// What to print or export.
    #[must_use]
    pub fn status(&self, now: u64) -> Status {
        Status {
            origin: self.origin.describe(),
            kids: self.keys.as_ref().map(IssuerKeys::kids).unwrap_or_default(),
            age: self.age(now),
            stale: self.past_ttl(now),
            expired: self.expired(now),
            last_error: self.last_error.clone(),
        }
    }

    fn read(&self) -> Result<String> {
        match &self.origin {
            Origin::File(path) => std::fs::read_to_string(path).map_err(|e| {
                WcError::with_detail(
                    Code::CONFIG_INVALID,
                    format!("{}: cannot read key set", path.display()),
                )
                .with_source(e)
            }),
            Origin::Url(url) => self.fetch(url),
        }
    }

    fn fetch(&self, url: &str) -> Result<String> {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(self.timeout))
            // A redirect on a trust-bundle fetch is somewhere else's answer to "which
            // keys are the issuer's". Same stance as `ControlPlaneClient`.
            .max_redirects(0)
            .http_status_as_error(false)
            .build()
            .into();

        let mut response = agent.get(url).call().map_err(|e| {
            WcError::with_detail(Code::CONFIG_INVALID, format!("{url}: unreachable")).with_source(e)
        })?;

        let status = response.status().as_u16();
        // A key set is kilobytes. The cap is here because the body is read before the
        // status is judged, so an error page — or a hostile endpoint — cannot be used
        // to make this process allocate.
        let body = response
            .body_mut()
            .with_config()
            .limit(1024 * 1024)
            .read_to_string()
            .map_err(|e| {
                WcError::with_detail(Code::CONFIG_INVALID, format!("{url}: cannot read response"))
                    .with_source(e)
            })?;

        if !(200..300).contains(&status) {
            return Err(WcError::with_detail(
                Code::CONFIG_INVALID,
                format!("{url}: returned {status}"),
            ));
        }
        Ok(body)
    }
}

/// How a process holds its issuer trust: pinned, or pulled from a key set.
///
/// Both are legitimate and the difference is operational, not cryptographic. A pinned
/// PEM is right for an air-gapped estate and for a mediator whose issuer key is
/// generational; a key set is right where rotation has to happen without touching every
/// host. What this type exists for is to keep the *call site* identical, so the refresh
/// loop cannot end up refreshing contracts against a trust set it forgot to refresh.
#[derive(Debug)]
pub enum Trust {
    /// Keys fixed at startup from a PEM. Never changes for the life of the process.
    Pinned(IssuerKeys),
    /// Keys from a published set, re-read on its TTL.
    Rotating(Box<JwksSource>),
}

impl Trust {
    /// The keys to verify against, refreshing first if the source is due.
    ///
    /// A refresh failure is returned as the second element rather than as an error,
    /// because it is usually not fatal — `JwksSource` keeps serving the cached set — and
    /// the caller wants to log it while carrying on. It becomes an error only when
    /// `keys` itself refuses, which is the staleness bound doing its job.
    pub fn keys(&mut self, now: u64) -> (Result<&IssuerKeys>, Option<WcError>) {
        match self {
            Trust::Pinned(keys) => (Ok(keys), None),
            Trust::Rotating(source) => {
                let failure = source.refresh(now).err();
                (source.keys(now), failure)
            }
        }
    }

    /// A one-line description for the startup banner.
    #[must_use]
    pub fn describe(&self, now: u64) -> String {
        match self {
            Trust::Pinned(keys) => format!("pinned key(s) {}", keys.kids().join(", ")),
            Trust::Rotating(source) => {
                let s = source.status(now);
                format!(
                    "{} from {} (ttl {}s){}",
                    if s.kids.is_empty() {
                        "no key".to_string()
                    } else {
                        format!("key(s) {}", s.kids.join(", "))
                    },
                    s.origin,
                    source.ttl,
                    if s.stale { ", STALE" } else { "" }
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    // Same fixture coordinates as `wc_core::contract::jwks_ingest`.
    const ES_X: &str = "ktLmuZwwCcx63nhx-fgvx5T_Ct8I8DC4aqxfFwViT70";
    const ES_Y: &str = "87OFL3uLtI_CltSCX5g8X4GsnwH-4RasPaKAs8US2Co";
    const ED_X: &str = "YlwgW8bKk8qBVesuj5HmIg03RABJ9CrwNCBu5WeKrAI";
    const NOW: u64 = 1_785_312_500;

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    struct Temp(PathBuf);

    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn write(document: &str) -> Temp {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let path = std::env::temp_dir().join(format!("wc-jwks-{}-{n}.json", std::process::id()));
        std::fs::write(&path, document).unwrap();
        Temp(path)
    }

    fn set(kids: &[&str]) -> String {
        let keys: Vec<String> = kids
            .iter()
            .map(|k| {
                format!(r#"{{"kty":"EC","crv":"P-256","x":"{ES_X}","y":"{ES_Y}","kid":"{k}"}}"#)
            })
            .collect();
        format!(r#"{{"keys":[{}]}}"#, keys.join(","))
    }

    #[test]
    fn a_file_source_loads_and_serves() {
        let f = write(&set(&["k1"]));
        let mut src = JwksSource::file(&f.0);
        let report = src.load(NOW).unwrap();
        assert_eq!(report.added, vec!["k1".to_string()]);
        assert!(src.keys(NOW).unwrap().get("k1").is_some());
    }

    #[test]
    fn a_withdrawn_key_stops_being_trusted() {
        // The reason a source replaces instead of merging. An issuer removes a
        // compromised key from its JWKS; if the refresh merged, the mediator would keep
        // verifying signatures made with it — and would report a healthy refresh while
        // doing so, which is the exact failure shape this repository keeps finding.
        let f = write(&set(&["good", "compromised"]));
        let mut src = JwksSource::file(&f.0).with_ttl(60);
        src.load(NOW).unwrap();
        assert!(src.keys(NOW).unwrap().get("compromised").is_some());

        std::fs::write(&f.0, set(&["good"])).unwrap();
        src.refresh(NOW + 61).unwrap().expect("the TTL had passed");

        let keys = src.keys(NOW + 61).unwrap();
        assert!(keys.get("good").is_some(), "the surviving key must stay");
        assert!(
            keys.get("compromised").is_none(),
            "a key the issuer withdrew must stop verifying"
        );
    }

    #[test]
    fn a_refresh_inside_the_ttl_does_not_re_read() {
        let f = write(&set(&["k1"]));
        let mut src = JwksSource::file(&f.0).with_ttl(300);
        src.load(NOW).unwrap();

        // Change the file, then refresh too early. Nothing should have been read — and
        // the assertion is on the *keys*, not on a call count, because that is what a
        // caller would actually notice.
        std::fs::write(&f.0, set(&["k2"])).unwrap();
        assert!(src.refresh(NOW + 299).unwrap().is_none());
        assert!(src.keys(NOW + 299).unwrap().get("k1").is_some());

        assert!(
            src.refresh(NOW + 300).unwrap().is_some(),
            "the TTL is inclusive"
        );
        assert!(src.keys(NOW + 300).unwrap().get("k2").is_some());
    }

    #[test]
    fn a_failed_refresh_keeps_serving_the_cached_set() {
        // The issuer being unreachable says nothing about the validity of keys already
        // held, and refusing every connection over it would be a self-inflicted outage.
        let f = write(&set(&["k1"]));
        let mut src = JwksSource::file(&f.0).with_ttl(60).with_max_stale(600);
        src.load(NOW).unwrap();

        std::fs::remove_file(&f.0).unwrap();
        let err = src.refresh(NOW + 61).unwrap_err();
        assert_eq!(err.code(), Code::CONFIG_INVALID);

        assert!(
            src.keys(NOW + 61).unwrap().get("k1").is_some(),
            "a failed refresh must not drop trust"
        );
        let status = src.status(NOW + 61);
        assert!(status.stale, "but it has to be visibly stale");
        assert!(!status.expired);
        assert!(status.last_error.is_some(), "and say why: {status:?}");
    }

    #[test]
    fn past_the_staleness_bound_it_refuses() {
        // The other half. Serving a cached set forever means revocation can no longer
        // reach this process, and nothing would have said so.
        let f = write(&set(&["k1"]));
        let mut src = JwksSource::file(&f.0).with_ttl(60).with_max_stale(600);
        src.load(NOW).unwrap();
        std::fs::remove_file(&f.0).unwrap();

        assert!(src.keys(NOW + 600).is_ok(), "the bound is inclusive");
        let err = src.keys(NOW + 601).unwrap_err();
        let text = format!("{err}");
        assert!(text.contains("staleness bound"), "{text}");
        assert!(
            text.contains("withdrawn key"),
            "the message has to say what the risk is, not just that a number was passed: {text}"
        );
        assert!(src.status(NOW + 601).expired);
    }

    #[test]
    fn a_source_that_never_loaded_refuses_rather_than_trusting_nothing_quietly() {
        // An empty `IssuerKeys` verifies nothing, so a source that returned one would
        // turn a misconfigured URL into "every contract has an unknown kid" — a true
        // statement that points at the wrong thing.
        let src = JwksSource::url("https://nowhere.invalid/jwks.json");
        let err = src.keys(NOW).unwrap_err();
        assert_eq!(err.code(), Code::CONFIG_INVALID);
        assert!(format!("{err}").contains("no issuer keys loaded"));
    }

    #[test]
    fn max_stale_below_the_ttl_is_clamped_up() {
        // Otherwise it reads as a tightening and behaves as an outage: the set would
        // expire before its own TTL, so the first refresh after expiry would find an
        // already-refusing source.
        let src = JwksSource::file("/nonexistent")
            .with_ttl(300)
            .with_max_stale(10);
        assert_eq!(src.max_stale, 300);
    }

    #[test]
    fn a_clock_that_moves_backwards_does_not_expire_a_good_set() {
        let f = write(&set(&["k1"]));
        let mut src = JwksSource::file(&f.0).with_ttl(60).with_max_stale(600);
        src.load(NOW).unwrap();
        assert!(!src.past_ttl(NOW - 10_000), "saturating, not wrapping");
        assert!(src.keys(NOW - 10_000).is_ok());
    }

    #[test]
    fn a_document_with_no_usable_key_leaves_the_previous_set_alone() {
        // A rotation that publishes a broken document must not take out a working
        // mediator. `add_jwks` refusing is what makes this hold — the fresh set never
        // gets swapped in.
        let f = write(&set(&["k1"]));
        let mut src = JwksSource::file(&f.0).with_ttl(60);
        src.load(NOW).unwrap();

        std::fs::write(
            &f.0,
            r#"{"keys":[{"kty":"RSA","n":"0vx7ag","e":"AQAB","kid":"r"}]}"#,
        )
        .unwrap();
        assert!(src.refresh(NOW + 61).is_err());
        assert!(
            src.keys(NOW + 61).unwrap().get("k1").is_some(),
            "the working key must survive a bad publish"
        );
    }

    #[test]
    fn the_status_names_what_is_trusted() {
        let f = write(&set(&["a", "b"]));
        let mut src = JwksSource::file(&f.0);
        src.load(NOW).unwrap();
        let s = src.status(NOW + 5);
        assert_eq!(s.kids, vec!["a".to_string(), "b".to_string()]);
        assert_eq!(s.age, Some(5));
        assert!(!s.stale && !s.expired && s.last_error.is_none());
        assert!(s.origin.contains("wc-jwks-"));
    }

    #[test]
    fn rotating_trust_refreshes_itself_at_the_call_site() {
        // The point of `Trust`: a caller that asks for keys gets refreshed keys. The
        // failure it prevents is a refresh loop that pulls new contracts every tick and
        // verifies them against the key set it loaded at boot — which works, silently,
        // right up until the rotation it was supposed to handle.
        let f = write(&set(&["k1"]));
        let mut trust = Trust::Rotating(Box::new(JwksSource::file(&f.0).with_ttl(60)));
        let (keys, failure) = trust.keys(NOW);
        assert!(keys.unwrap().get("k1").is_some());
        assert!(failure.is_none());

        std::fs::write(&f.0, set(&["k2"])).unwrap();
        let (keys, failure) = trust.keys(NOW + 61);
        assert!(failure.is_none());
        let keys = keys.unwrap();
        assert!(
            keys.get("k2").is_some(),
            "the caller never asked to refresh"
        );
        assert!(keys.get("k1").is_none());
    }

    #[test]
    fn rotating_trust_reports_a_refresh_failure_without_failing_the_call() {
        let f = write(&set(&["k1"]));
        let mut trust = Trust::Rotating(Box::new(
            JwksSource::file(&f.0).with_ttl(60).with_max_stale(600),
        ));
        assert!(trust.keys(NOW).0.is_ok());
        std::fs::remove_file(&f.0).unwrap();

        let (keys, failure) = trust.keys(NOW + 61);
        assert!(keys.is_ok(), "still serving the cached set");
        assert!(
            failure.is_some(),
            "and telling the caller it could not refresh"
        );

        // Past the bound both halves refuse.
        let (keys, _) = trust.keys(NOW + 601);
        assert!(keys.is_err());
    }

    #[test]
    fn pinned_trust_needs_no_source_and_says_so() {
        let mut keys = IssuerKeys::default();
        keys.add_jwks(&set(&["pinned-1"])).unwrap();
        let mut trust = Trust::Pinned(keys);
        assert!(trust.keys(NOW).0.unwrap().get("pinned-1").is_some());
        assert!(trust.describe(NOW).contains("pinned key(s) pinned-1"));
    }

    #[test]
    fn an_ed25519_key_arrives_through_a_source_too() {
        let f = write(&format!(
            r#"{{"keys":[{{"kty":"OKP","crv":"Ed25519","x":"{ED_X}","kid":"ed-1"}}]}}"#
        ));
        let mut src = JwksSource::file(&f.0);
        assert_eq!(src.load(NOW).unwrap().added, vec!["ed-1".to_string()]);
    }
}
