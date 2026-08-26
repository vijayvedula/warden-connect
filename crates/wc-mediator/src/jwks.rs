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
    /// A file on disk — a SPIRE bundle written by `spire-server bundle show -format
    /// spiffe`, or a ConfigMap mount. Re-read on the same TTL, because a mounted file
    /// changes under a running process without the process being told.
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
pub enum KeySource {
    /// Keys fixed at startup from a PEM. Never changes for the life of the process.
    Pinned(IssuerKeys),
    /// Keys from a published set, re-read on its TTL.
    Rotating(Box<JwksSource>),
}

impl KeySource {
    /// The keys to verify against, refreshing first if the source is due.
    ///
    /// A refresh failure is returned as the second element rather than as an error,
    /// because it is usually not fatal — `JwksSource` keeps serving the cached set — and
    /// the caller wants to log it while carrying on. It becomes an error only when
    /// `keys` itself refuses, which is the staleness bound doing its job.
    pub fn keys(&mut self, now: u64) -> (Result<&IssuerKeys>, Option<WcError>) {
        match self {
            KeySource::Pinned(keys) => (Ok(keys), None),
            KeySource::Rotating(source) => {
                let failure = source.refresh(now).err();
                (source.keys(now), failure)
            }
        }
    }

    /// A one-line description for the startup banner.
    #[must_use]
    pub fn describe(&self, now: u64) -> String {
        match self {
            KeySource::Pinned(keys) => format!("pinned key(s) {}", keys.kids().join(", ")),
            KeySource::Rotating(source) => {
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
    pub(super) const ES_X: &str = "ktLmuZwwCcx63nhx-fgvx5T_Ct8I8DC4aqxfFwViT70";
    pub(super) const ES_Y: &str = "87OFL3uLtI_CltSCX5g8X4GsnwH-4RasPaKAs8US2Co";
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
        // The point of `KeySource`: a caller that asks for keys gets refreshed keys. The
        // failure it prevents is a refresh loop that pulls new contracts every tick and
        // verifies them against the key set it loaded at boot — which works, silently,
        // right up until the rotation it was supposed to handle.
        let f = write(&set(&["k1"]));
        let mut trust = KeySource::Rotating(Box::new(JwksSource::file(&f.0).with_ttl(60)));
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
        let mut trust = KeySource::Rotating(Box::new(
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
        let mut trust = KeySource::Pinned(keys);
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

/// The flags that choose where issuer trust comes from, already looked up.
///
/// Values rather than an argument slice, so the two binaries that need this — the inline
/// mediator and the gateway verifier — share the RULES without sharing a flag parser. The rules
/// are the valuable part: exactly one source, `--kid`/`--alg` refused alongside a key set, and
/// the set loaded at startup rather than on the first request.
#[derive(Debug, Default)]
pub struct TrustSpec<'a> {
    /// A pinned PEM.
    pub issuer_pub: Option<&'a str>,
    /// The key id that PEM is registered under. Only meaningful with `issuer_pub`.
    pub kid: Option<&'a str>,
    /// Its algorithm; `ES256` when absent. Only meaningful with `issuer_pub`.
    pub alg: Option<&'a str>,
    /// A published key set.
    pub jwks_url: Option<&'a str>,
    /// A key set on disk.
    pub jwks_file: Option<&'a str>,
    /// Seconds between key-set reads.
    pub jwks_ttl: Option<u64>,
    /// Seconds a cached set is still served while the fetch is failing.
    pub jwks_max_stale: Option<u64>,
}

/// Resolve issuer trust: one pinned PEM, or a key set that rotates.
///
/// Returns the source and, for a key set, what loading it skipped — the caller logs that,
/// because a partly-loaded set is usable and worth saying out loud.
///
/// # Errors
///
/// No source, more than one source, `--kid`/`--alg` beside a key set, an unreadable PEM, an
/// algorithm this project does not accept, or a key set that will not load. The ambiguous case
/// is refused rather than resolved by precedence: an operator who passes two sources has two
/// different beliefs about where trust comes from, and silently honouring one means trusting
/// something they did not think they were.
pub fn build_trust(
    spec: &TrustSpec<'_>,
    now: u64,
) -> std::result::Result<(KeySource, Option<JwksReport>), String> {
    let chosen = [
        spec.issuer_pub.map(|_| "--issuer-pub"),
        spec.jwks_url.map(|_| "--jwks-url"),
        spec.jwks_file.map(|_| "--jwks-file"),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();

    match chosen.as_slice() {
        [] => Err(
            "no issuer trust: pass --issuer-pub PEM --kid KID, or --jwks-url URL, \
                   or --jwks-file FILE"
                .to_string(),
        ),
        [_] => Ok(()),
        many => Err(format!(
            "{} were all given; issuer trust has one source, and choosing for you would \
             mean verifying against a key set you did not mean",
            many.join(" and ")
        )),
    }?;

    if let Some(pem_path) = spec.issuer_pub {
        let kid = spec
            .kid
            .ok_or_else(|| "--kid is required with --issuer-pub".to_string())?;
        let pem = std::fs::read(pem_path).map_err(|e| format!("read {pem_path}: {e}"))?;
        let mut keys = IssuerKeys::new();
        match spec.alg.unwrap_or("ES256") {
            "ES256" => keys.add_ec_pem(kid, &pem, wc_core::contract::Algorithm::ES256),
            "ES384" => keys.add_ec_pem(kid, &pem, wc_core::contract::Algorithm::ES384),
            "EdDSA" | "Ed25519" => keys.add_ed_pem(kid, &pem),
            other => return Err(format!("{other:?} is not an accepted contract algorithm")),
        }
        .map_err(|e| e.to_string())?;
        return Ok((KeySource::Pinned(keys), None));
    }

    // `--kid` and `--alg` name one key; a key set names its own, so accepting them together
    // would suggest they narrow it. They do not.
    for (given, name) in [(spec.kid, "kid"), (spec.alg, "alg")] {
        if given.is_some() {
            return Err(format!(
                "--{name} applies to --issuer-pub only; a key set carries its own kid \
                 and algorithm, so this flag would have no effect"
            ));
        }
    }

    let mut source = match (spec.jwks_url, spec.jwks_file) {
        (Some(url), _) => JwksSource::url(url),
        (_, Some(file)) => JwksSource::file(file),
        _ => unreachable!("one source was chosen above"),
    };
    if let Some(ttl) = spec.jwks_ttl {
        source = source.with_ttl(ttl);
    }
    if let Some(max) = spec.jwks_max_stale {
        source = source.with_max_stale(max);
    }

    // Loaded here so a bad URL is a startup failure. Deferring it to the first request would
    // mean the process starts, reports healthy, and denies everything.
    let report = source
        .load(now)
        .map_err(|e| format!("issuer key set unusable, refusing to start: {e}"))?;
    Ok((KeySource::Rotating(Box::new(source)), Some(report)))
}

#[cfg(test)]
mod trust_spec_tests {
    //! The selection rules, tested once for both binaries that apply them.
    //!
    //! They were a private function inside `connect-mediate` and had no direct coverage: the
    //! rules were exercised only by starting the binary. Sharing them with the gateway verifier
    //! made that worth fixing — a rule two processes depend on should not be checked by neither.
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    const PUB: &[u8] = include_bytes!("../../../fixtures/keys/test_issuer_es256_pub.pem");

    /// A PEM on disk at a path unique to the CALLER.
    ///
    /// The first version keyed the path on the process id alone. Four tests call this, the
    /// harness runs them in parallel, and they raced on one file: a truncated read while another
    /// thread was writing made the PEM unparseable about one run in three. The `who` argument is
    /// what makes each test's file its own.
    fn pem_on_disk(who: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("wc-trust-{}-{who}.pem", std::process::id()));
        std::fs::write(&p, PUB).unwrap();
        p
    }

    #[test]
    fn a_pinned_pem_needs_a_kid() {
        let p = pem_on_disk("a_pinned_pem_needs_a_kid");
        let spec = TrustSpec {
            issuer_pub: p.to_str(),
            ..TrustSpec::default()
        };
        let e = build_trust(&spec, 0).unwrap_err();
        assert!(e.contains("--kid"), "{e}");
    }

    #[test]
    fn a_pinned_pem_with_a_kid_resolves() {
        let p = pem_on_disk("a_pinned_pem_with_a_kid_resolves");
        let spec = TrustSpec {
            issuer_pub: p.to_str(),
            kid: Some("wc-test-es256"),
            ..TrustSpec::default()
        };
        let (source, report) = build_trust(&spec, 0).unwrap();
        assert!(matches!(source, KeySource::Pinned(_)));
        assert!(
            report.is_none(),
            "a pinned PEM is not a key set and has no report"
        );
    }

    #[test]
    fn no_source_at_all_is_refused() {
        let e = build_trust(&TrustSpec::default(), 0).unwrap_err();
        assert!(e.contains("no issuer trust"), "{e}");
    }

    #[test]
    fn two_sources_are_refused_rather_than_resolved_by_precedence() {
        // An operator who passes two has two different beliefs about where trust comes from.
        let p = pem_on_disk("two_sources_are_refused_rather_than_resolved_by_precedence");
        let spec = TrustSpec {
            issuer_pub: p.to_str(),
            kid: Some("wc-test-es256"),
            jwks_url: Some("https://example.invalid/jwks.json"),
            ..TrustSpec::default()
        };
        let e = build_trust(&spec, 0).unwrap_err();
        assert!(e.contains("one source"), "{e}");
        assert!(
            e.contains("--issuer-pub") && e.contains("--jwks-url"),
            "{e}"
        );
    }

    #[test]
    fn kid_and_alg_are_refused_beside_a_key_set() {
        // They name one key; a key set names its own. Accepting them would suggest they narrow
        // it, and they do not.
        for (kid, alg, want) in [(Some("k"), None, "--kid"), (None, Some("ES256"), "--alg")] {
            let spec = TrustSpec {
                jwks_file: Some("/nonexistent.json"),
                kid,
                alg,
                ..TrustSpec::default()
            };
            let e = build_trust(&spec, 0).unwrap_err();
            assert!(e.contains(want), "{e}");
            assert!(e.contains("no effect"), "{e}");
        }
    }

    #[test]
    fn an_algorithm_this_project_does_not_accept_is_refused() {
        // No HMAC, anywhere. A symmetric algorithm here would mean the verifier could mint.
        let p = pem_on_disk("an_algorithm_this_project_does_not_accept_is_refused");
        let spec = TrustSpec {
            issuer_pub: p.to_str(),
            kid: Some("k"),
            alg: Some("HS256"),
            ..TrustSpec::default()
        };
        let e = build_trust(&spec, 0).unwrap_err();
        assert!(e.contains("not an accepted contract algorithm"), "{e}");
    }

    #[test]
    fn an_unreadable_pem_is_a_startup_failure() {
        let spec = TrustSpec {
            issuer_pub: Some("/nonexistent/issuer.pem"),
            kid: Some("k"),
            ..TrustSpec::default()
        };
        assert!(build_trust(&spec, 0).is_err());
    }

    #[test]
    fn a_key_set_that_will_not_load_refuses_to_start() {
        // Deferring the load to the first request would mean the process starts, reports
        // healthy, and denies everything — the failure that takes longest to diagnose.
        let spec = TrustSpec {
            jwks_file: Some("/nonexistent/jwks.json"),
            ..TrustSpec::default()
        };
        let e = build_trust(&spec, 0).unwrap_err();
        assert!(e.contains("refusing to start"), "{e}");
    }

    #[test]
    fn a_key_set_on_disk_resolves_and_rotates() {
        let dir = std::env::temp_dir().join(format!("wc-jwks-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("jwks.json");
        // A real key, not an empty document: an empty set is correctly refused as "0 keys and
        // none usable", which the first version of this test discovered the hard way.
        std::fs::write(
            &path,
            format!(
                r#"{{"keys":[{{"kty":"EC","crv":"P-256","x":"{}","y":"{}","kid":"k1"}}]}}"#,
                super::tests::ES_X,
                super::tests::ES_Y
            ),
        )
        .unwrap();
        let spec = TrustSpec {
            jwks_file: path.to_str(),
            jwks_ttl: Some(30),
            jwks_max_stale: Some(90),
            ..TrustSpec::default()
        };
        let (source, report) = build_trust(&spec, 0).unwrap();
        assert!(matches!(source, KeySource::Rotating(_)));
        assert!(report.is_some(), "a key set must report what it loaded");
        std::fs::remove_dir_all(&dir).ok();
    }
}
