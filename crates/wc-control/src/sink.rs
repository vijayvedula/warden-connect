//! Evidence sinks: format × transport × filter × delivery
//! (`docs/08-lld.md` §8.5.8, §7.8).
//!
//! A sink ships a projected view of a lifecycle event to something outside the
//! control plane — a SIEM, a security lake, a WORM store, an IdP's shared-signals
//! endpoint.
//!
//! # The two delivery semantics, and why the difference matters
//!
//! - [`Delivery::FailSafe`] — ship on a best-effort basis. A sink failure is
//!   recorded and alarmed, but the operation proceeds. Losing a SIEM copy is not
//!   worth failing an issuance for, because the tamper-evident chain already holds
//!   the authoritative record.
//! - [`Delivery::Blocking`] — the operation does **not** proceed until the sink
//!   acknowledges. Used in regulated estates where authority must not exist
//!   without a durable external trail. §7.8: *blocking evidence sink unavailable →
//!   deny*.
//!
//! That is the whole reason a sink knows about delivery at all: it is the
//! difference between evidence being a byproduct and evidence being a
//! precondition.
//!
//! Wire formats match Warden core's `sink.rs`/`ocsf.rs` so one SIEM pipeline
//! ingests both planes; compatibility is held by golden vectors, not by shared
//! code (§8.3).

use std::path::{Path, PathBuf};

use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::Deserialize;

use wc_core::error::{Code, Result, WcError};

use crate::evidence::{LifecycleEvent, Severity};

/// Wire format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    /// OCSF activity/finding events, for a SIEM or security lake.
    Ocsf,
    /// A signed CAEP Security Event Token (RFC 8417), for shared signals.
    Caep,
}

/// Where events go.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transport {
    /// Append JSON lines to a local file.
    File {
        /// Destination path.
        path: PathBuf,
    },
    /// POST to an HTTPS collector.
    Webhook {
        /// Destination URL.
        endpoint: String,
    },
}

/// Which events a sink wants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Filter {
    /// Everything.
    All,
    /// Only denials.
    Deny,
    /// High and critical severity.
    HighRisk,
    /// Revocation and quarantine only.
    Revocation,
}

/// Whether the operation waits for this sink.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Delivery {
    /// Best effort; failures are alarmed, the operation proceeds.
    FailSafe,
    /// The operation does not proceed until this sink acknowledges.
    Blocking,
}

/// A destination for lifecycle events.
///
/// The built-in [`Sink`] (file or webhook, OCSF or CAEP) implements this, and it
/// is the paved road. The trait exists because **warden-connect deliberately does
/// not ship a database adapter**: an embedded store would add an operational
/// dependency — backups, migrations, connection pools, a second thing to make
/// highly available — in exchange for no capability the append-only log and its
/// tamper-evident chain do not already provide.
///
/// So persistence beyond the chain is an *integration*, not a feature. An estate
/// that wants its events in Postgres, Kafka, Splunk or an internal bus implements
/// this trait and pushes the result into [`crate::evidence::Evidence::with_sinks`].
/// No fork, no patch to an enum.
///
/// # What an implementation owes the caller
///
/// * [`EventSink::delivery`] is a contract, not a hint. Returning
///   [`Delivery::Blocking`] means the operation the caller was about to perform is
///   refused when `ship` fails — so a blocking sink must not be something that is
///   routinely unavailable.
/// * `ship` must be idempotent under retry, because a fail-safe sink that errors
///   after a partial write will be called again for the next event and never for
///   the one it dropped.
/// * The **chain is authoritative, not the sink.** A sink is where evidence goes
///   to be useful; it is never where evidence goes to be true. Nothing here may
///   assume it is the only copy.
pub trait EventSink: std::fmt::Debug + Send + Sync {
    /// Operator-facing name, used in metrics, warnings and alarms.
    fn name(&self) -> &str;

    /// Whether this event is in scope for this destination.
    fn accepts(&self, event: &LifecycleEvent) -> bool;

    /// Deliver one event.
    fn ship(&self, event: &LifecycleEvent, now: u64) -> Result<()>;

    /// Whether the caller waits, and is refused on failure.
    fn delivery(&self) -> Delivery;
}

/// One configured destination.
#[derive(Debug, Clone)]
pub struct Sink {
    /// Operator-facing name, used in metrics and alarms.
    pub name: String,
    /// Wire format.
    pub format: Format,
    /// Where to send.
    pub transport: Transport,
    /// What to send.
    pub filter: Filter,
    /// Whether the caller waits.
    pub delivery: Delivery,
    /// ES256 signing key (PKCS#8 PEM), required for [`Format::Caep`].
    pub key: Option<Vec<u8>>,
    /// Request timeout for webhook transports.
    pub timeout_secs: u64,
}

impl Sink {
    /// A local-file sink, the default for air-gapped and test deployments.
    #[must_use]
    pub fn file(name: &str, path: impl Into<PathBuf>, format: Format) -> Sink {
        Sink {
            name: name.to_string(),
            format,
            transport: Transport::File { path: path.into() },
            filter: Filter::All,
            delivery: Delivery::FailSafe,
            key: None,
            timeout_secs: 10,
        }
    }

    /// Whether this sink wants a given event.
    #[must_use]
    pub fn accepts(&self, event: &LifecycleEvent) -> bool {
        match self.filter {
            Filter::All => true,
            Filter::Deny => event.is_denial(),
            Filter::HighRisk => event.severity() >= Severity::High,
            Filter::Revocation => event.is_containment(),
        }
    }

    /// Render the event in this sink's format.
    pub fn render(&self, event: &LifecycleEvent, now: u64) -> Result<String> {
        match self.format {
            Format::Ocsf => Ok(event.to_ocsf(now).to_string()),
            Format::Caep => {
                let key_pem = self.key.as_deref().ok_or_else(|| {
                    WcError::with_detail(
                        Code::BLOCKING_SINK_UNAVAILABLE,
                        format!("sink {} is CAEP but has no signing key", self.name),
                    )
                })?;
                let key = EncodingKey::from_ec_pem(key_pem).map_err(|e| {
                    WcError::with_detail(
                        Code::BLOCKING_SINK_UNAVAILABLE,
                        format!("sink {}: signing key is not a PKCS#8 EC PEM", self.name),
                    )
                    .with_source(e)
                })?;
                let mut header = Header::new(Algorithm::ES256);
                // RFC 8417: a SET is a JWT with `typ` set so a receiver cannot
                // confuse it with an access token.
                header.typ = Some("secevent+jwt".to_string());
                jsonwebtoken::encode(&header, &event.to_caep(now), &key).map_err(|e| {
                    WcError::with_detail(
                        Code::BLOCKING_SINK_UNAVAILABLE,
                        format!("sink {}: cannot sign the security event token", self.name),
                    )
                    .with_source(e)
                })
            }
        }
    }

    /// Ship one event. Returns `Ok(())` only when the destination accepted it.
    pub fn ship(&self, event: &LifecycleEvent, now: u64) -> Result<()> {
        let payload = self.render(event, now)?;
        match &self.transport {
            Transport::File { path } => {
                use std::io::Write;
                if let Some(parent) = path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                let mut file = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .map_err(|e| sink_err(&self.name, path.display().to_string(), e))?;
                writeln!(file, "{payload}")
                    .map_err(|e| sink_err(&self.name, path.display().to_string(), e))?;
                // Blocking delivery means durable, not merely written: an
                // unflushed page cache is not a trail.
                if self.delivery == Delivery::Blocking {
                    file.sync_data()
                        .map_err(|e| sink_err(&self.name, path.display().to_string(), e))?;
                }
                Ok(())
            }
            Transport::Webhook { endpoint } => {
                let agent: ureq::Agent = ureq::Agent::config_builder()
                    .timeout_global(Some(std::time::Duration::from_secs(self.timeout_secs)))
                    .max_redirects(0)
                    // Handle statuses here rather than letting the transport turn
                    // them into opaque errors: "collector returned 503" and
                    // "collector is unreachable" need different operator responses.
                    .http_status_as_error(false)
                    .build()
                    .into();
                let content_type = match self.format {
                    Format::Ocsf => "application/json",
                    Format::Caep => "application/secevent+jwt",
                };
                let response = agent
                    .post(endpoint)
                    .header("content-type", content_type)
                    .send(payload)
                    .map_err(|e| {
                        WcError::with_detail(
                            Code::BLOCKING_SINK_UNAVAILABLE,
                            format!("sink {}: POST {endpoint} failed", self.name),
                        )
                        .with_source(e)
                    })?;

                let status = response.status().as_u16();
                if (200..300).contains(&status) {
                    Ok(())
                } else {
                    Err(WcError::with_detail(
                        Code::BLOCKING_SINK_UNAVAILABLE,
                        format!("sink {}: {endpoint} returned {status}", self.name),
                    ))
                }
            }
        }
    }
}

fn sink_err(name: &str, target: String, e: std::io::Error) -> WcError {
    WcError::with_detail(
        Code::BLOCKING_SINK_UNAVAILABLE,
        format!("sink {name}: {target}: {e}"),
    )
    .with_source(e)
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// A `[[sink]]` table in `connect.toml`. Deliberately the same shape as Warden
/// core's, so an operator writes one stanza style for both planes.
#[derive(Debug, Deserialize)]
pub struct SinkSpec {
    /// Operator-facing name.
    pub name: String,
    /// `ocsf` | `caep`.
    pub format: Format,
    /// `file` | `webhook`.
    pub transport: String,
    /// Destination for `webhook`.
    #[serde(default)]
    pub endpoint: Option<String>,
    /// Destination for `file`.
    #[serde(default)]
    pub path: Option<String>,
    /// Defaults to `all`.
    #[serde(default = "default_filter")]
    pub filter: Filter,
    /// Defaults to `fail-safe`.
    #[serde(default = "default_delivery")]
    pub delivery: Delivery,
    /// PEM path for a CAEP signing key.
    #[serde(default)]
    pub key: Option<String>,
    /// Webhook timeout.
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_filter() -> Filter {
    Filter::All
}

fn default_delivery() -> Delivery {
    Delivery::FailSafe
}

fn default_timeout() -> u64 {
    10
}

#[derive(Debug, Deserialize)]
struct SinkFile {
    #[serde(default)]
    sink: Vec<SinkSpec>,
}

impl SinkSpec {
    /// Resolve a spec into a usable sink, reading any key file from disk.
    pub fn into_sink(self) -> Result<Sink> {
        let transport = match self.transport.as_str() {
            "file" => Transport::File {
                path: PathBuf::from(
                    self.path
                        .ok_or_else(|| config_err(&self.name, "a file sink needs `path`"))?,
                ),
            },
            "webhook" => Transport::Webhook {
                endpoint: self
                    .endpoint
                    .ok_or_else(|| config_err(&self.name, "a webhook sink needs `endpoint`"))?,
            },
            other => {
                return Err(config_err(
                    &self.name,
                    format!("unknown transport {other:?}"),
                ))
            }
        };

        let key = match self.key {
            Some(path) => Some(
                std::fs::read(&path)
                    .map_err(|e| config_err(&self.name, format!("cannot read key {path}: {e}")))?,
            ),
            None => None,
        };

        // Catching this at load time rather than at the first quarantine is the
        // point: a CAEP sink with no key is a containment path that fails when it
        // is needed most.
        if self.format == Format::Caep && key.is_none() {
            return Err(config_err(&self.name, "a caep sink needs `key`"));
        }

        Ok(Sink {
            name: self.name,
            format: self.format,
            transport,
            filter: self.filter,
            delivery: self.delivery,
            key,
            timeout_secs: self.timeout_secs,
        })
    }
}

fn config_err(name: &str, detail: impl std::fmt::Display) -> WcError {
    WcError::with_detail(Code::CONFIG_INVALID, format!("sink {name}: {detail}"))
}

/// Load every `[[sink]]` from a TOML config.
///
/// A malformed sink is [`Code::CONFIG_INVALID`], which §8.13 says means *refuse to
/// start*: a control plane that boots with a silently-dropped evidence sink
/// believes it is recording when it is not.
pub fn load_specs(config_path: impl AsRef<Path>) -> Result<Vec<Sink>> {
    let path = config_path.as_ref();
    let text = std::fs::read_to_string(path).map_err(|e| {
        WcError::with_detail(
            Code::CONFIG_INVALID,
            format!("{}: cannot read config", path.display()),
        )
        .with_source(e)
    })?;
    let parsed: SinkFile = toml::from_str(&text).map_err(|e| {
        WcError::with_detail(
            Code::CONFIG_INVALID,
            format!("{}: cannot parse config", path.display()),
        )
        .with_source(e)
    })?;
    parsed.sink.into_iter().map(SinkSpec::into_sink).collect()
}

/// Partition sinks by whether the caller must wait for them.
#[must_use]
pub fn partition(sinks: &[Sink]) -> (Vec<&Sink>, Vec<&Sink>) {
    sinks.iter().partition(|s| s.delivery == Delivery::Blocking)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

impl EventSink for Sink {
    fn name(&self) -> &str {
        &self.name
    }

    fn accepts(&self, event: &LifecycleEvent) -> bool {
        Sink::accepts(self, event)
    }

    fn ship(&self, event: &LifecycleEvent, now: u64) -> Result<()> {
        Sink::ship(self, event, now)
    }

    fn delivery(&self) -> Delivery {
        self.delivery
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::evidence::{EventKind, LifecycleEvent};
    use serde_json::Value;
    use std::sync::atomic::{AtomicU32, Ordering};

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    const CAEP_KEY: &[u8] = include_bytes!("../../../fixtures/keys/test_anchor_priv.pem");

    fn tmp(tag: &str) -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!("wc-sink-{}-{tag}-{n}", std::process::id()));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn event(kind: EventKind) -> LifecycleEvent {
        LifecycleEvent::new(kind, "human:priya@org").with_reason("test")
    }

    // --- filters ---

    #[test]
    fn filters_select_the_right_events() {
        let mut sink = Sink::file("s", "x", Format::Ocsf);

        sink.filter = Filter::All;
        assert!(sink.accepts(&event(EventKind::Discover)));

        sink.filter = Filter::Deny;
        assert!(!sink.accepts(&event(EventKind::Mint)));
        assert!(sink.accepts(&event(EventKind::AdmissionDenied)));
        assert!(sink.accepts(&event(EventKind::ContractDenied)));

        sink.filter = Filter::HighRisk;
        assert!(!sink.accepts(&event(EventKind::Discover)));
        assert!(sink.accepts(&event(EventKind::DriftMaterial)));
        assert!(sink.accepts(&event(EventKind::Quarantine)));

        sink.filter = Filter::Revocation;
        assert!(!sink.accepts(&event(EventKind::Mint)));
        assert!(sink.accepts(&event(EventKind::Revoke)));
        assert!(sink.accepts(&event(EventKind::Quarantine)));
        assert!(!sink.accepts(&event(EventKind::DriftMaterial)));
    }

    // --- file transport ---

    #[test]
    fn a_file_sink_appends_one_json_line_per_event() {
        let dir = tmp("file");
        let path = dir.join("ocsf.jsonl");
        let sink = Sink::file("lake", &path, Format::Ocsf);

        sink.ship(&event(EventKind::Register), 1_000).unwrap();
        sink.ship(&event(EventKind::Mint), 1_001).unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.lines().count(), 2);
        let first: Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        assert_eq!(first["class_uid"], 3004);
        assert!(first["time"].is_number());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_file_sink_creates_missing_directories() {
        let dir = tmp("nested");
        let path = dir.join("deep").join("nested").join("ocsf.jsonl");
        Sink::file("s", &path, Format::Ocsf)
            .ship(&event(EventKind::Register), 1)
            .unwrap();
        assert!(path.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- CAEP ---

    #[test]
    fn a_caep_sink_emits_a_signed_security_event_token() {
        let dir = tmp("caep");
        let path = dir.join("set.jsonl");
        let mut sink = Sink::file("ssf", &path, Format::Caep);
        sink.key = Some(CAEP_KEY.to_vec());

        sink.ship(&event(EventKind::Quarantine), 1_000).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        let jwt = text.lines().next().unwrap();
        assert_eq!(jwt.split('.').count(), 3, "a SET is a signed JWT");

        // The header must mark it a security event token, so a receiver cannot
        // mistake it for an access token.
        let header = jsonwebtoken::decode_header(jwt).unwrap();
        assert_eq!(header.typ.as_deref(), Some("secevent+jwt"));
        assert_eq!(header.alg, Algorithm::ES256);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_caep_sink_without_a_key_fails_loudly() {
        let sink = Sink::file("ssf", "x", Format::Caep);
        let err = sink.render(&event(EventKind::Quarantine), 1).unwrap_err();
        assert_eq!(err.code(), Code::BLOCKING_SINK_UNAVAILABLE);
        assert!(err.detail().contains("no signing key"));
    }

    // --- webhook transport ---

    #[test]
    fn a_webhook_sink_posts_and_honours_the_status() {
        use std::io::{BufRead, BufReader, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        let handle = std::thread::spawn(move || {
            let mut bodies: Vec<String> = Vec::new();
            // First request gets 202, second gets 500.
            for (i, status) in ["202 Accepted", "500 Internal Server Error"]
                .iter()
                .enumerate()
            {
                let (mut stream, _) = listener.accept().unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut length = 0usize;
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap() == 0 {
                        break;
                    }
                    if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        length = v.trim().parse().unwrap_or(0);
                    }
                    if line == "\r\n" || line == "\n" {
                        break;
                    }
                }
                let mut body = vec![0u8; length];
                std::io::Read::read_exact(&mut reader, &mut body).unwrap();
                bodies.push(String::from_utf8_lossy(&body).into_owned());
                let _ = i;
                stream
                    .write_all(
                        format!(
                            "HTTP/1.1 {status}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                        )
                        .as_bytes(),
                    )
                    .unwrap();
                stream.flush().unwrap();
            }
            bodies
        });

        let sink = Sink {
            name: "collector".to_string(),
            format: Format::Ocsf,
            transport: Transport::Webhook {
                endpoint: format!("http://127.0.0.1:{port}/ocsf"),
            },
            filter: Filter::All,
            delivery: Delivery::Blocking,
            key: None,
            timeout_secs: 5,
        };

        // 2xx is an acknowledgement.
        sink.ship(&event(EventKind::Mint), 1_000).unwrap();

        // Anything else is not, and a blocking sink must say so rather than
        // pretend the trail exists.
        let err = sink.ship(&event(EventKind::Mint), 1_001).unwrap_err();
        assert_eq!(err.code(), Code::BLOCKING_SINK_UNAVAILABLE);
        assert!(err.detail().contains("500"));

        let bodies = handle.join().unwrap();
        assert_eq!(bodies.len(), 2);
        let posted: Value = serde_json::from_str(&bodies[0]).unwrap();
        assert_eq!(posted["class_uid"], 3004);
    }

    #[test]
    fn an_unreachable_webhook_is_an_error() {
        let sink = Sink {
            name: "dead".to_string(),
            format: Format::Ocsf,
            // Port 1 is reserved and will refuse.
            transport: Transport::Webhook {
                endpoint: "http://127.0.0.1:1/ocsf".to_string(),
            },
            filter: Filter::All,
            delivery: Delivery::Blocking,
            key: None,
            timeout_secs: 2,
        };
        let err = sink.ship(&event(EventKind::Mint), 1).unwrap_err();
        assert_eq!(err.code(), Code::BLOCKING_SINK_UNAVAILABLE);
    }

    // --- configuration ---

    #[test]
    fn specs_load_from_toml() {
        let dir = tmp("cfg");
        let cfg = dir.join("connect.toml");
        std::fs::write(
            &cfg,
            r#"
[[sink]]
name = "security-lake"
format = "ocsf"
transport = "webhook"
endpoint = "https://collector.internal/ocsf"
filter = "all"
delivery = "fail-safe"

[[sink]]
name = "regulated-evidence"
format = "ocsf"
transport = "file"
path = "evidence/ocsf.jsonl"
filter = "high-risk"
delivery = "blocking"
"#,
        )
        .unwrap();

        let sinks = load_specs(&cfg).unwrap();
        assert_eq!(sinks.len(), 2);
        assert_eq!(sinks[0].delivery, Delivery::FailSafe);
        assert_eq!(sinks[1].filter, Filter::HighRisk);
        assert_eq!(sinks[1].delivery, Delivery::Blocking);

        let (blocking, fail_safe) = partition(&sinks);
        assert_eq!(blocking.len(), 1);
        assert_eq!(fail_safe.len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_misconfigured_sink_refuses_to_load() {
        let dir = tmp("badcfg");
        let cases = [
            // webhook with no endpoint
            "[[sink]]\nname = \"a\"\nformat = \"ocsf\"\ntransport = \"webhook\"\n",
            // file with no path
            "[[sink]]\nname = \"b\"\nformat = \"ocsf\"\ntransport = \"file\"\n",
            // unknown transport
            "[[sink]]\nname = \"c\"\nformat = \"ocsf\"\ntransport = \"carrier-pigeon\"\n",
            // caep with no signing key — a containment path that would fail when
            // it is needed most
            "[[sink]]\nname = \"d\"\nformat = \"caep\"\ntransport = \"file\"\npath = \"x\"\n",
        ];
        for (i, body) in cases.iter().enumerate() {
            let cfg = dir.join(format!("bad{i}.toml"));
            std::fs::write(&cfg, body).unwrap();
            let err = load_specs(&cfg).unwrap_err();
            assert_eq!(err.code(), Code::CONFIG_INVALID, "case {i}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_config_is_an_error_not_an_empty_list() {
        // Silently proceeding with no sinks is how an estate believes it is
        // recording when it is not.
        let err = load_specs("/nonexistent/connect.toml").unwrap_err();
        assert_eq!(err.code(), Code::CONFIG_INVALID);
    }
}
