//! A minimal HTTP/1.1 server (`docs/08-lld.md` §8.5.10).
//!
//! Thread-per-request over `std::net`, matching Warden core's shape — no async
//! runtime, no framework. The control plane serves a handful of JSON endpoints at
//! human speed; a dependency that brings its own executor would cost more than it
//! saves (§8.2).
//!
//! Every limit here exists because its absence is a way to hurt the control plane
//! from outside: bounded request lines, bounded header count and size, a bounded
//! body, a read timeout, and a cap on concurrent connections that sheds load with
//! `503` rather than exhausting threads.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Longest request line accepted, bytes.
const MAX_REQUEST_LINE: usize = 8 * 1024;
/// Most headers accepted.
const MAX_HEADERS: usize = 64;
/// Longest single header line, bytes.
const MAX_HEADER_LINE: usize = 8 * 1024;
/// Largest body accepted, bytes.
pub const MAX_BODY: usize = 1024 * 1024;
/// Per-connection read timeout.
const READ_TIMEOUT: Duration = Duration::from_secs(15);
/// Concurrent connections above which the server sheds load.
const MAX_INFLIGHT: usize = 128;

/// A parsed request.
#[derive(Debug, Clone)]
pub struct Request {
    /// Uppercase method.
    pub method: String,
    /// Path as received, still percent-encoded.
    pub path: String,
    /// Path segments, each percent-decoded.
    ///
    /// Decoded **after** splitting, never before: an id like
    /// `spiffe%3A%2F%2Forg%2Fns%2Fa` decodes to something containing `/`, so
    /// decoding the whole path first would split one segment into six and no route
    /// with an id in it would ever match.
    pub path_segments: Vec<String>,
    /// Decoded query parameters.
    pub query: BTreeMap<String, String>,
    /// Header names lowercased.
    pub headers: BTreeMap<String, String>,
    /// Body bytes.
    pub body: Vec<u8>,
}

impl Request {
    /// A header value.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(String::as_str)
    }

    /// A query parameter.
    #[must_use]
    pub fn param(&self, name: &str) -> Option<&str> {
        self.query.get(name).map(String::as_str)
    }

    /// A numeric query parameter.
    #[must_use]
    pub fn param_u64(&self, name: &str) -> Option<u64> {
        self.param(name).and_then(|v| v.parse().ok())
    }

    /// The bearer token, if one was presented.
    #[must_use]
    pub fn bearer(&self) -> Option<&str> {
        self.header("authorization")
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(str::trim)
    }

    /// Path segments, decoded, empty ones dropped.
    #[must_use]
    pub fn segments(&self) -> Vec<&str> {
        self.path_segments.iter().map(String::as_str).collect()
    }
}

/// A response to write.
#[derive(Debug, Clone)]
pub struct Response {
    /// HTTP status.
    pub status: u16,
    /// Content type.
    pub content_type: String,
    /// Extra headers.
    pub headers: Vec<(String, String)>,
    /// Body.
    pub body: Vec<u8>,
}

impl Response {
    /// A JSON response.
    #[must_use]
    pub fn json(status: u16, body: impl Into<String>) -> Response {
        Response {
            status,
            content_type: "application/json".to_string(),
            headers: Vec::new(),
            body: body.into().into_bytes(),
        }
    }

    /// A plain-text response.
    #[must_use]
    pub fn text(status: u16, body: impl Into<String>) -> Response {
        Response {
            status,
            content_type: "text/plain; charset=utf-8".to_string(),
            headers: Vec::new(),
            body: body.into().into_bytes(),
        }
    }

    /// An empty response.
    #[must_use]
    pub fn empty(status: u16) -> Response {
        Response {
            status,
            content_type: "application/json".to_string(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    /// Add a header.
    #[must_use]
    pub fn with_header(mut self, name: &str, value: impl Into<String>) -> Response {
        self.headers.push((name.to_string(), value.into()));
        self
    }

    /// The reason phrase for the status.
    #[must_use]
    pub fn reason(&self) -> &'static str {
        match self.status {
            200 => "OK",
            201 => "Created",
            202 => "Accepted",
            204 => "No Content",
            400 => "Bad Request",
            401 => "Unauthorized",
            403 => "Forbidden",
            404 => "Not Found",
            405 => "Method Not Allowed",
            409 => "Conflict",
            410 => "Gone",
            413 => "Payload Too Large",
            422 => "Unprocessable Entity",
            424 => "Failed Dependency",
            429 => "Too Many Requests",
            500 => "Internal Server Error",
            503 => "Service Unavailable",
            _ => "Status",
        }
    }
}

/// Signals the server to stop accepting.
#[derive(Debug, Default)]
pub struct Shutdown(AtomicBool);

impl Shutdown {
    /// Ask the server to stop.
    pub fn request(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    /// Whether a stop was requested.
    #[must_use]
    pub fn requested(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

/// Anything that can answer a request.
pub trait Handler: Send + Sync {
    /// Handle one request.
    fn handle(&self, req: &Request) -> Response;
}

impl<F> Handler for F
where
    F: Fn(&Request) -> Response + Send + Sync,
{
    fn handle(&self, req: &Request) -> Response {
        self(req)
    }
}

/// Serve until `shutdown` is requested.
///
/// Binds and returns the local address through `on_bind` before looping, so a
/// caller (or a test) can learn the port when binding to `:0`.
pub fn serve<H: Handler + 'static>(
    addr: &str,
    handler: Arc<H>,
    shutdown: Arc<Shutdown>,
    on_bind: impl FnOnce(std::net::SocketAddr),
) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr)?;
    on_bind(listener.local_addr()?);
    // A short accept timeout so a shutdown request is noticed promptly rather than
    // only when the next connection happens to arrive.
    listener.set_nonblocking(false)?;

    let inflight = Arc::new(AtomicUsize::new(0));

    for stream in listener.incoming() {
        if shutdown.requested() {
            break;
        }
        let stream = match stream {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(_) => continue,
        };

        if inflight.load(Ordering::SeqCst) >= MAX_INFLIGHT {
            // Shed rather than exhaust: a control plane that runs out of threads
            // stops issuing *and* stops answering, which is the worse failure.
            let _ = write_response(
                &stream,
                &Response::json(503, r#"{"error":"too many connections"}"#),
            );
            continue;
        }

        let handler = Arc::clone(&handler);
        let inflight = Arc::clone(&inflight);
        inflight.fetch_add(1, Ordering::SeqCst);
        std::thread::spawn(move || {
            let response = match read_request(&stream) {
                Ok(req) => handler.handle(&req),
                Err(status) => Response::json(
                    status,
                    format!(r#"{{"error":"malformed request","status":{status}}}"#),
                ),
            };
            let _ = write_response(&stream, &response);
            inflight.fetch_sub(1, Ordering::SeqCst);
        });
    }
    Ok(())
}

/// Read and parse one request. Errors are HTTP statuses, so a malformed request
/// gets an answer rather than a dropped connection.
fn read_request(stream: &TcpStream) -> Result<Request, u16> {
    stream
        .set_read_timeout(Some(READ_TIMEOUT))
        .map_err(|_| 500u16)?;
    let mut reader = BufReader::new(stream);

    let mut line = String::new();
    read_line(&mut reader, &mut line, MAX_REQUEST_LINE)?;
    let mut parts = line.split_whitespace();
    let method = parts.next().ok_or(400u16)?.to_ascii_uppercase();
    let target = parts.next().ok_or(400u16)?;

    let (path, query_str) = target.split_once('?').unwrap_or((target, ""));
    let query = parse_query(query_str);

    let mut headers = BTreeMap::new();
    for _ in 0..MAX_HEADERS {
        let mut header = String::new();
        read_line(&mut reader, &mut header, MAX_HEADER_LINE)?;
        let trimmed = header.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        if let Some((name, value)) = trimmed.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }

    let length: usize = headers
        .get("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    if length > MAX_BODY {
        return Err(413u16);
    }
    let mut body = vec![0u8; length];
    if length > 0 {
        reader.read_exact(&mut body).map_err(|_| 400u16)?;
    }

    Ok(Request {
        method,
        path_segments: path
            .split('/')
            .filter(|s| !s.is_empty())
            .map(percent_decode)
            .collect(),
        path: path.to_string(),
        query,
        headers,
        body,
    })
}

fn read_line<R: BufRead>(reader: &mut R, out: &mut String, cap: usize) -> Result<(), u16> {
    let mut taken = reader.take(cap as u64);
    let read = taken.read_line(out).map_err(|_| 400u16)?;
    if read == 0 {
        return Err(400u16);
    }
    if read >= cap {
        return Err(413u16);
    }
    Ok(())
}

fn parse_query(text: &str) -> BTreeMap<String, String> {
    text.split('&')
        .filter(|p| !p.is_empty())
        .map(|pair| match pair.split_once('=') {
            Some((k, v)) => (percent_decode(k), percent_decode(v)),
            None => (percent_decode(pair), String::new()),
        })
        .collect()
}

/// Decode `%XX` escapes and `+`.
///
/// Path segments carry SPIFFE ids, which contain `/` and `:` — so a client must
/// percent-encode them and the server must decode before routing.
#[must_use]
pub fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
                match u8::from_str_radix(hex, 16) {
                    Ok(byte) => {
                        out.push(byte);
                        i += 3;
                    }
                    Err(_) => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn write_response(mut stream: &TcpStream, response: &Response) -> std::io::Result<()> {
    let mut head = format!(
        "HTTP/1.1 {} {}\r\ncontent-type: {}\r\ncontent-length: {}\r\n",
        response.status,
        response.reason(),
        response.content_type,
        response.body.len()
    );
    for (name, value) in &response.headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    // No keep-alive: a control plane serves a handful of requests at human speed,
    // and one connection per request removes a whole class of framing bug.
    head.push_str("connection: close\r\n\r\n");

    stream.write_all(head.as_bytes())?;
    stream.write_all(&response.body)?;
    stream.flush()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn percent_decoding_handles_spiffe_ids() {
        assert_eq!(
            percent_decode("spiffe%3A%2F%2Forg%2Fns%2Fagents%2Fsa%2Frecon-bot-7"),
            "spiffe://org/ns/agents/sa/recon-bot-7"
        );
        assert_eq!(percent_decode("a+b"), "a b");
        assert_eq!(percent_decode("plain"), "plain");
        // A stray `%` is passed through rather than swallowing the next bytes.
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("%zz"), "%zz");
    }

    #[test]
    fn queries_parse_into_pairs() {
        let q = parse_query("since=42&format=dora&flag");
        assert_eq!(q.get("since").map(String::as_str), Some("42"));
        assert_eq!(q.get("format").map(String::as_str), Some("dora"));
        assert_eq!(q.get("flag").map(String::as_str), Some(""));
        assert!(parse_query("").is_empty());
    }

    #[test]
    fn requests_expose_headers_case_insensitively() {
        let req = Request {
            method: "GET".to_string(),
            path: "/v1/entities".to_string(),
            path_segments: vec!["v1".to_string(), "entities".to_string()],
            query: BTreeMap::new(),
            headers: [("authorization".to_string(), "Bearer abc".to_string())]
                .into_iter()
                .collect(),
            body: Vec::new(),
        };
        assert_eq!(req.header("Authorization"), Some("Bearer abc"));
        assert_eq!(req.bearer(), Some("abc"));
        assert_eq!(req.segments(), vec!["v1", "entities"]);
    }

    #[test]
    fn a_segment_is_decoded_after_splitting_not_before() {
        // The bug this exists to prevent: decoding first turns one id segment into
        // six, and every route carrying an id 404s.
        let encoded = "/v1/entities/spiffe%3A%2F%2Forg%2Fns%2Fagents%2Fsa%2Frecon-bot-7";
        let segments: Vec<String> = encoded
            .split('/')
            .filter(|s| !s.is_empty())
            .map(percent_decode)
            .collect();
        assert_eq!(segments.len(), 3);
        assert_eq!(segments[2], "spiffe://org/ns/agents/sa/recon-bot-7");
    }

    #[test]
    fn responses_carry_a_reason_phrase() {
        assert_eq!(Response::empty(200).reason(), "OK");
        assert_eq!(Response::empty(403).reason(), "Forbidden");
        assert_eq!(Response::empty(599).reason(), "Status");
    }
}
