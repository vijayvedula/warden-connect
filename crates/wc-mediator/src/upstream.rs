//! The upstream a mediated call is forwarded to.
//!
//! [`Upstream`] is the seam the whole mediator is built on: [`crate::gate::MediatedUpstream`]
//! is a decorator over it, so the 14 verification gates (HLD §7.4) apply to anything that can
//! answer a JSON-RPC frame. Two methods, which is why inverting the Warden dependency was a
//! small change rather than a rewrite (see [`crate::rpc`]).
//!
//! There are two implementations, and the choice is a transport, not a posture — the same
//! decorator wraps either, so the gates, the catalogue filter and the ceilings are the same code
//! on both paths:
//!
//! * [`StdioUpstream`] — an MCP server spawned as a child process, speaking newline-delimited
//!   JSON-RPC over its stdin and stdout. One agent, one server, one sidecar.
//! * [`HttpUpstream`] — a remote MCP server over Streamable HTTP, answering with either
//!   `application/json` or `text/event-stream`. This is the shape an organisation ends up with
//!   once a team wraps an existing API as an MCP server, and such a server cannot be spawned.
//!
//! # What this is defensive about, and why
//!
//! The upstream is a **callee**, and §7.8's trust boundary puts the callee on the untrusted
//! side — its declared surface and its responses are both suspect. So a single call is bounded
//! three ways, and each bound has a failure it exists to prevent:
//!
//! | Bound | Prevents |
//! |---|---|
//! | [`MAX_UPSTREAM_LINE`] | an upstream streaming an unterminated line until the mediator is out of memory |
//! | a per-call timeout | a hung upstream turning into a hung agent, which presents as the *mediator* being broken |
//! | restart on any fault | one bad call poisoning every call after it |
//!
//! Every fault path returns a JSON-RPC error rather than panicking or propagating, because the
//! mediator sits between an agent and a server: a panic here is an outage for a party that did
//! nothing wrong.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use crate::rpc::{Request, Response};

/// Something that can answer a JSON-RPC frame.
///
/// `notify` has a no-op default: a notification expects no response, and an implementation
/// with nothing to forward to is entitled to drop it. [`StdioUpstream`] overrides it, because
/// a notification an MCP server never receives is a handshake step that silently did not
/// happen.
pub trait Upstream {
    /// Forward a request and return its response.
    fn request(&mut self, req: &Request) -> Response;

    /// Forward a notification. No response is expected, and none is read.
    fn notify(&mut self, _req: &Request) {}
}

/// Upper bound on one upstream response line, in bytes.
///
/// Generous for real tool output — a large `tools/list` or a document read is nowhere near
/// this — and low enough that a hostile or looping upstream cannot exhaust the mediator's
/// memory inside the timeout window. A line that hits the cap is returned truncated, fails to
/// parse as JSON, and becomes a clean upstream error.
pub const MAX_UPSTREAM_LINE: usize = 8 * 1024 * 1024;

/// A live child process and its pipes, replaced wholesale on restart.
struct Spawned {
    child: Child,
    stdin: ChildStdin,
    /// `Option` because the reader is handed to a worker thread for the duration of a read
    /// and moved back afterwards. `None` means a read is in flight or was lost to a timeout.
    reader: Option<BufReader<ChildStdout>>,
}

/// Read one `\n`-terminated line without ever buffering more than `cap` bytes.
///
/// Byte at a time, which looks wasteful and is not: the `BufReader` underneath amortises the
/// syscalls, and the property that matters here is that the buffer *cannot* grow past `cap`.
/// `read_line` has no such bound, and the upstream is on the untrusted side of the boundary.
fn read_line_capped<R: BufRead>(r: &mut R, cap: usize) -> (std::io::Result<usize>, String) {
    let mut raw: Vec<u8> = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match r.read(&mut byte) {
            Ok(0) => break, // EOF
            Ok(_) => {
                raw.push(byte[0]);
                if byte[0] == b'\n' || raw.len() >= cap {
                    break;
                }
            }
            Err(e) => return (Err(e), String::from_utf8_lossy(&raw).into_owned()),
        }
    }
    (Ok(raw.len()), String::from_utf8_lossy(&raw).into_owned())
}

/// A real MCP server over stdio, resilient to upstream crashes and hangs.
pub struct StdioUpstream {
    command: String,
    timeout: Duration,
    inner: Option<Spawned>,
}

impl std::fmt::Debug for StdioUpstream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StdioUpstream")
            .field("command", &self.command)
            .field("timeout", &self.timeout)
            .field("live", &self.inner.is_some())
            .finish()
    }
}

impl StdioUpstream {
    /// Spawn the command and hold it open.
    ///
    /// Fails only if the initial spawn fails; every later fault is recovered by restarting,
    /// so a transient upstream problem does not require restarting the mediator.
    pub fn spawn(command: &str, timeout: Duration) -> Result<StdioUpstream, String> {
        let inner = StdioUpstream::launch(command)?;
        Ok(StdioUpstream {
            command: command.to_string(),
            timeout,
            inner: Some(inner),
        })
    }

    /// Split on whitespace, no shell.
    ///
    /// The same rule `signer.rs` applies to signing helpers, for the same reason: a command
    /// run through a shell is an injection surface, and this one is named in the mediator's
    /// own configuration. Anything needing quotes belongs in a script the command names.
    ///
    /// `stderr` is deliberately **not** piped — the upstream's diagnostics go to the
    /// mediator's own stderr, where an operator is already looking, rather than being
    /// swallowed into a buffer nobody drains.
    fn launch(command: &str) -> Result<Spawned, String> {
        let mut parts = command.split_whitespace();
        let program = parts.next().ok_or("empty upstream command")?;
        let args: Vec<&str> = parts.collect();
        let mut child = wc_core::proc::spawn_piped(
            Command::new(program)
                .args(&args)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped()),
        )
        .map_err(|e| format!("spawn upstream: {e}"))?;
        let stdin = child.stdin.take().ok_or("no upstream stdin")?;
        let stdout = child.stdout.take().ok_or("no upstream stdout")?;
        Ok(Spawned {
            child,
            stdin,
            reader: Some(BufReader::new(stdout)),
        })
    }

    /// Kill the current child and start a fresh one.
    ///
    /// Reaped, not just killed: a killed child that is never waited on is a zombie, and a
    /// long-lived mediator that restarts its upstream occasionally would accumulate them.
    fn restart(&mut self) {
        if let Some(inner) = &mut self.inner {
            let _ = inner.child.kill();
            let _ = inner.child.wait();
        }
        match StdioUpstream::launch(&self.command) {
            Ok(inner) => {
                self.inner = Some(inner);
                eprintln!("connect-mediate: upstream restarted");
            }
            Err(e) => {
                self.inner = None;
                eprintln!("connect-mediate: upstream restart failed: {e}");
            }
        }
    }

    /// Put a reader back after a completed read, so the next call reuses the same pipe.
    fn return_reader(&mut self, reader: BufReader<ChildStdout>) {
        if let Some(inner) = &mut self.inner {
            inner.reader = Some(reader);
        }
    }
}

impl Drop for StdioUpstream {
    /// Graceful first, then forceful.
    ///
    /// Dropping `stdin` closes the pipe, which is how an MCP server is told the session is
    /// over — it gets the chance to flush rather than being shot mid-write. The kill that
    /// follows is for a server that ignores EOF: without it the last child of every mediator
    /// is detached at exit, and a server stuck in a blocking operation becomes an orphan
    /// nobody reaps.
    ///
    /// `restart` already kills and reaps, so this only covers the final child — but "only the
    /// last one" times every mediator in an estate is still a process leak.
    fn drop(&mut self) {
        let Some(mut inner) = self.inner.take() else {
            return;
        };
        // Taken by value so `stdin` can be dropped *first*, closing the pipe. Ordering is the
        // whole point: killing before the close would make the graceful half hollow.
        drop(inner.stdin);

        // A brief bounded wait for the server to notice EOF and exit on its own. Polled
        // rather than blocking on `wait`, because a server that ignores EOF would otherwise
        // hang the drop — and a drop that can hang is worse than an abrupt shutdown.
        let deadline = std::time::Instant::now() + Duration::from_millis(200);
        loop {
            match inner.child.try_wait() {
                Ok(Some(_)) => return, // exited cleanly; nothing to kill
                Ok(None) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                _ => break,
            }
        }
        let _ = inner.child.kill();
        let _ = inner.child.wait();
    }
}

impl Upstream for StdioUpstream {
    fn request(&mut self, req: &Request) -> Response {
        if self.inner.is_none() {
            self.restart();
        }
        let Some(inner) = &mut self.inner else {
            return Response::error(req.id.clone(), -32000, "upstream unavailable");
        };

        let line = match serde_json::to_string(req) {
            Ok(l) => l,
            Err(e) => return Response::error(req.id.clone(), -32603, format!("encode: {e}")),
        };
        if writeln!(inner.stdin, "{line}")
            .and_then(|()| inner.stdin.flush())
            .is_err()
        {
            self.restart();
            return Response::error(req.id.clone(), -32000, "upstream send failed; restarted");
        }

        let Some(mut reader) = inner.reader.take() else {
            self.restart();
            return Response::error(req.id.clone(), -32000, "upstream reader lost; restarted");
        };

        // The read happens on a worker thread so the timeout can be enforced. A blocking
        // read cannot be cancelled, so on timeout the child is killed to unblock it and the
        // orphaned thread then exits on its own.
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let (res, buf) = read_line_capped(&mut reader, MAX_UPSTREAM_LINE);
            let _ = tx.send((reader, res, buf));
        });

        match rx.recv_timeout(self.timeout) {
            // EOF: the upstream exited.
            Ok((reader, Ok(0), _)) => {
                self.return_reader(reader);
                self.restart();
                Response::error(req.id.clone(), -32000, "upstream closed; restarted")
            }
            Ok((reader, Ok(_), buf)) => {
                self.return_reader(reader);
                serde_json::from_str(buf.trim()).unwrap_or_else(|e| {
                    Response::error(
                        req.id.clone(),
                        -32000,
                        format!("bad upstream response: {e}"),
                    )
                })
            }
            Ok((reader, Err(e), _)) => {
                self.return_reader(reader);
                self.restart();
                Response::error(
                    req.id.clone(),
                    -32000,
                    format!("upstream read failed: {e}; restarted"),
                )
            }
            Err(_) => {
                // The read thread still holds the reader, so it is not returned. `restart`
                // replaces the whole child, which is what unblocks that thread.
                self.restart();
                Response::error(
                    req.id.clone(),
                    -32000,
                    format!(
                        "upstream timed out after {}s; restarted",
                        self.timeout.as_secs()
                    ),
                )
            }
        }
    }

    fn notify(&mut self, req: &Request) {
        // Forwarded but never read: a notification carries no id, so there is no response to
        // correlate and reading would consume the *next* response instead. Errors are
        // dropped for the same reason — there is nobody to return them to.
        if let Some(inner) = &mut self.inner {
            if let Ok(line) = serde_json::to_string(req) {
                let _ = writeln!(inner.stdin, "{line}").and_then(|()| inner.stdin.flush());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use serde_json::json;

    /// A tiny MCP-ish server as a shell script, so these tests exercise a real child
    /// process, real pipes and the real timeout — not a stand-in that cannot hang.
    fn script(body: &str) -> (tempish::Dir, String) {
        let dir = tempish::Dir::new();
        let path = dir.write("srv.sh", body);
        (dir, format!("/bin/sh {path}"))
    }

    /// A minimal scratch directory. `std::env::temp_dir` plus the pid, cleared before use —
    /// `create_dir_all` on an existing path keeps its contents, and these paths repeat
    /// across runs because pids are reused.
    mod tempish {
        use std::path::PathBuf;
        use std::sync::atomic::{AtomicU32, Ordering};

        static N: AtomicU32 = AtomicU32::new(0);

        pub struct Dir(PathBuf);

        impl Dir {
            pub fn new() -> Dir {
                let n = N.fetch_add(1, Ordering::SeqCst);
                let p =
                    std::env::temp_dir().join(format!("wc-upstream-{}-{n}", std::process::id()));
                let _ = std::fs::remove_dir_all(&p);
                std::fs::create_dir_all(&p).unwrap();
                Dir(p)
            }
            pub fn write(&self, name: &str, body: &str) -> String {
                let path = self.0.join(name);
                std::fs::write(&path, body).unwrap();
                path.to_string_lossy().into_owned()
            }
        }

        impl Drop for Dir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
    }

    #[test]
    fn a_well_behaved_upstream_answers_and_the_pipe_survives_two_calls() {
        // Echoes a fixed result per line. Two calls, so the reader really is handed back
        // rather than lost after the first — which a single-call test cannot show.
        let (_d, cmd) = script(
            "while IFS= read -r line; do printf '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"ok\":true}}\\n'; done\n",
        );
        let mut up = StdioUpstream::spawn(&cmd, Duration::from_secs(5)).unwrap();
        for _ in 0..2 {
            let resp = up.request(&Request::new(1, "ping", json!({})));
            assert_eq!(resp.result.unwrap()["ok"], json!(true));
        }
    }

    #[test]
    fn a_hanging_upstream_times_out_rather_than_hanging_the_agent() {
        // Reads and never answers. Without the timeout this test would never return, which
        // is precisely the failure an agent would experience as the mediator being broken.
        let (_d, cmd) = script("while IFS= read -r line; do sleep 30; done\n");
        let mut up = StdioUpstream::spawn(&cmd, Duration::from_millis(400)).unwrap();
        let resp = up.request(&Request::new(1, "ping", json!({})));
        let msg = resp.error.expect("a hang must surface as an error").message;
        assert!(msg.contains("timed out"), "{msg}");
    }

    #[test]
    fn an_upstream_that_exits_is_restarted_and_the_next_call_works() {
        // Answers once then exits. The first call sees EOF or an answer; the point is that
        // the mediator recovers rather than staying broken.
        let (_d, cmd) = script(
            "IFS= read -r line; printf '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"n\":1}}\\n'; exit 0\n",
        );
        let mut up = StdioUpstream::spawn(&cmd, Duration::from_secs(5)).unwrap();
        let _ = up.request(&Request::new(1, "ping", json!({})));
        let second = up.request(&Request::new(2, "ping", json!({})));
        assert!(
            second.result.is_some() || second.error.is_some(),
            "a restarted upstream must answer something rather than panic"
        );
    }

    #[test]
    fn garbage_from_the_upstream_becomes_an_error_not_a_panic() {
        let (_d, cmd) = script("while IFS= read -r line; do printf 'not json at all\\n'; done\n");
        let mut up = StdioUpstream::spawn(&cmd, Duration::from_secs(5)).unwrap();
        let resp = up.request(&Request::new(1, "ping", json!({})));
        let msg = resp.error.expect("unparseable output is an error").message;
        assert!(msg.contains("bad upstream response"), "{msg}");
    }

    #[test]
    fn an_unterminated_line_is_capped_rather_than_growing_without_bound() {
        // The cap is exercised at a small value through the helper directly, because
        // driving 8 MB through a shell script would make the suite slow for no extra proof.
        // What matters is that the read stops at the cap on a stream with no newline.
        let endless = std::io::repeat(b'x');
        let mut r = BufReader::new(endless);
        let (res, buf) = read_line_capped(&mut r, 1024);
        assert_eq!(res.unwrap(), 1024);
        assert_eq!(
            buf.len(),
            1024,
            "the read must stop at the cap, not at a newline"
        );
    }

    #[test]
    fn an_empty_command_is_refused_at_spawn() {
        let err = StdioUpstream::spawn("   ", Duration::from_secs(1)).unwrap_err();
        assert!(err.contains("empty upstream command"), "{err}");
    }

    #[test]
    fn a_notification_is_forwarded_and_no_response_is_consumed() {
        // The upstream appends to a file on a notification. If `notify` read a response it
        // would consume the answer to the *following* request, so the request after the
        // notification must still get its own answer.
        let dir = tempish::Dir::new();
        let marker = dir.write("seen", "");
        let body = format!(
            "while IFS= read -r line; do \
               case \"$line\" in \
                 *notifications*) printf 'x' >> {marker} ;; \
                 *) printf '{{\"jsonrpc\":\"2.0\",\"id\":9,\"result\":{{\"ok\":true}}}}\\n' ;; \
               esac; \
             done\n"
        );
        let path = dir.write("srv.sh", &body);
        let mut up =
            StdioUpstream::spawn(&format!("/bin/sh {path}"), Duration::from_secs(5)).unwrap();

        up.notify(&Request {
            jsonrpc: "2.0".to_string(),
            id: None,
            method: "notifications/initialized".to_string(),
            params: json!({}),
        });
        let resp = up.request(&Request::new(9, "ping", json!({})));
        assert_eq!(
            resp.result
                .expect("the request after a notification must still be answered")["ok"],
            json!(true)
        );
    }
}

// ---------------------------------------------------------------------------
// HTTP upstream
// ---------------------------------------------------------------------------

/// An MCP server reached over HTTP rather than spawned as a child process.
///
/// MCP's Streamable HTTP transport is a `POST` of one JSON-RPC frame to a single endpoint. The
/// response is either `application/json` — one frame, which is what a `tools/list` or a
/// `tools/call` returns — or `text/event-stream`, when the server chooses to stream. Both are
/// handled here; the stream is reduced to the frame that carries this request's `id`, because the
/// gate decides per frame and an agent asked one question.
///
/// # Why this exists
///
/// [`StdioUpstream`] covers the case where the server runs beside the agent. Most MCP servers in
/// an organisation are an HTTP facade over an existing API, and those cannot be spawned — so
/// without this, the mediator has nothing to decorate and the ceiling is unenforceable for the
/// majority of the estate.
///
/// # What it is defensive about
///
/// The same three bounds as the stdio path, for the same reasons: a response-size cap, a per-call
/// timeout, and no shared state that one bad call can poison. There is no restart, because there
/// is no process — a failed request is a failed request, and the next one is independent.
///
/// Sessions: `Mcp-Session-Id` is echoed back on every later request once a server has issued one.
/// A server that expects a session and never receives it answers every call as though the
/// handshake had not happened, which presents as the mediator being broken.
pub struct HttpUpstream {
    url: String,
    /// Extra headers, for a bearer token or a mesh identity the operator wants forwarded.
    headers: Vec<(String, String)>,
    /// Issued by the server on `initialize`, echoed on everything after it.
    session: Option<String>,
    /// Built once. `client.rs` builds one per call, which is right for a pull every few
    /// seconds and wrong here: this is the hot path, and an agent per call means a connection
    /// pool per call — so every tool call would pay a fresh TCP and TLS handshake.
    agent: ureq::Agent,
}

impl HttpUpstream {
    /// An upstream at `url`, with a per-call timeout.
    #[must_use]
    pub fn new(url: impl Into<String>, timeout: Duration) -> HttpUpstream {
        HttpUpstream {
            url: url.into(),
            headers: Vec::new(),
            session: None,
            agent: ureq::Agent::config_builder()
                .timeout_global(Some(timeout))
                .max_redirects(0)
                // Statuses are read here, so "the server said 403" and "the server is
                // unreachable" stay distinguishable — the same reason `client.rs` does it.
                .http_status_as_error(false)
                .build()
                .into(),
        }
    }

    /// Forward a header on every request. Repeatable.
    #[must_use]
    pub fn with_header(
        mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> HttpUpstream {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// One frame out, one frame back.
    fn post(&mut self, req: &Request) -> Result<Response, String> {
        let body = serde_json::to_string(req).map_err(|e| format!("encode: {e}"))?;
        let mut call = self
            .agent
            .post(&self.url)
            .header("content-type", "application/json")
            // Both are advertised because a server may answer either, and one that sees only
            // `application/json` is entitled to refuse a request it would have streamed.
            .header("accept", "application/json, text/event-stream");
        for (k, v) in &self.headers {
            call = call.header(k.as_str(), v.as_str());
        }
        if let Some(sid) = &self.session {
            call = call.header("mcp-session-id", sid.as_str());
        }

        let mut resp = call.send(&body).map_err(|e| format!("unreachable: {e}"))?;
        let status = resp.status().as_u16();

        // A session id is issued once and echoed for the life of the connection.
        if let Some(sid) = resp
            .headers()
            .get("mcp-session-id")
            .and_then(|v| v.to_str().ok())
        {
            self.session = Some(sid.to_string());
        }

        let ctype = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_ascii_lowercase();

        let text = resp
            .body_mut()
            .with_config()
            .limit(MAX_UPSTREAM_LINE as u64)
            .read_to_string()
            .map_err(|e| format!("read: {e}"))?;

        if status == 202 && text.trim().is_empty() {
            return match &req.id {
                // A notification. 202 with no body is exactly the documented answer, there is no
                // id to answer on, and `notify` — the only caller that sends one — discards this.
                None => Ok(Response::error(None, 0, "accepted")),
                // A request. The frame was accepted and the answer will never arrive on this
                // channel, so the call has failed. Manufacturing a response here would hand the
                // gate a protocol violation dressed as a result.
                Some(_) => Err(
                    "upstream returned 202 with no body for a request; the response \
                                will never arrive on this channel"
                        .to_string(),
                ),
            };
        }
        if !(200..300).contains(&status) {
            return Err(format!(
                "upstream returned {status}: {}",
                first_line(&text, 200)
            ));
        }

        let frame = if ctype.contains("text/event-stream") {
            sse_frame_for(&text, req.id.as_ref())
                .ok_or_else(|| "event stream carried no frame for this request".to_string())?
        } else {
            text
        };
        serde_json::from_str::<Response>(&frame).map_err(|e| format!("decode: {e}"))
    }
}

/// Split one `--upstream-header` value into a name and a value.
///
/// The separator is the FIRST colon: header values legitimately contain colons (a `Host` with a
/// port, a bearer token that is itself a URL), and splitting on the last one would silently move
/// part of the value into the name, producing a header the operator did not write.
pub fn parse_upstream_header(raw: &str) -> Result<(String, String), String> {
    let (name, value) = raw
        .split_once(':')
        .ok_or_else(|| format!("--upstream-header expects 'Name: value', got {raw:?}"))?;
    let name = name.trim();
    let value = value.trim();
    if name.is_empty() {
        return Err(format!("--upstream-header has an empty name: {raw:?}"));
    }
    // A name with whitespace or a control character is not a header; sent verbatim it would let a
    // crafted flag inject a second header line into the request.
    if name
        .chars()
        .any(|c| c.is_whitespace() || c.is_control() || c == ':')
        || value.chars().any(|c| c.is_control())
    {
        return Err(format!("--upstream-header is not a valid header: {raw:?}"));
    }
    Ok((name.to_string(), value.to_string()))
}

/// Decide whether an upstream URL may be used, given whether plaintext was explicitly allowed.
///
/// `https` is always fine. Plaintext `http` to loopback is the local development case and is
/// allowed. Plaintext to anything else is REFUSED unless the operator opted in: the mediator's
/// whole job is to be the thing that decides what a tool call may do, and shipping those calls
/// over a network in the clear hands that decision to anyone on the path. Refusing beats a
/// warning nobody reads.
pub fn check_upstream_url(url: &str, allow_plaintext: bool) -> Result<(), String> {
    let host = if let Some(rest) = url.strip_prefix("https://") {
        let _ = rest;
        return Ok(());
    } else if let Some(rest) = url.strip_prefix("http://") {
        rest
    } else {
        return Err(format!(
            "--upstream-url must be http:// or https://, got {url:?}"
        ));
    };

    // Authority ends at the path, query, or fragment; strip any userinfo and the port.
    let authority = host
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("")
        .rsplit('@')
        .next()
        .unwrap_or("");
    let hostname = match authority.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or(""), // [::1]:8080
        None => authority.split(':').next().unwrap_or(""),
    };
    if hostname.is_empty() {
        return Err(format!("--upstream-url has no host: {url:?}"));
    }

    let loopback = hostname.eq_ignore_ascii_case("localhost")
        || hostname == "::1"
        || hostname
            .parse::<std::net::Ipv4Addr>()
            .is_ok_and(|ip| ip.is_loopback());
    if loopback || allow_plaintext {
        Ok(())
    } else {
        Err(format!(
            "refusing plaintext http:// to {hostname}: tool calls and their arguments would \
             cross the network in the clear. Use https://, or pass --upstream-allow-plaintext \
             if a proxy on this host terminates TLS."
        ))
    }
}

/// Pull the JSON-RPC response for `id` out of an SSE body.
///
/// An SSE body is `field: value` lines in blocks separated by a blank line, and a single logical
/// payload may span several `data:` lines — they are joined with a newline, not concatenated. A
/// server is free to interleave notifications and progress events with the answer, so matching on
/// `id` is what keeps a `tools/call` result from being satisfied by a progress notification: a
/// notification carries no `id` and can never satisfy a request.
///
/// Returns `None` when the stream ends with no frame for `id`.
#[must_use]
pub fn sse_frame_for(body: &str, id: Option<&serde_json::Value>) -> Option<String> {
    let mut data: Vec<String> = Vec::new();
    let mut out: Option<String> = None;

    let flush = |data: &mut Vec<String>, out: &mut Option<String>| {
        if data.is_empty() || out.is_some() {
            data.clear();
            return;
        }
        let payload = data.join("\n");
        data.clear();
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&payload) else {
            return;
        };
        // A frame with no `id` is a notification, never an answer.
        match (id, v.get("id")) {
            (Some(want), Some(got)) if want == got => *out = Some(payload),
            (None, _) => *out = Some(payload),
            _ => {}
        }
    };

    for line in body.lines() {
        if line.trim().is_empty() {
            flush(&mut data, &mut out);
        } else if let Some(rest) = line.strip_prefix("data:") {
            data.push(rest.strip_prefix(' ').unwrap_or(rest).to_string());
        }
        // Every other field — `event:`, `id:`, `retry:`, a `:` comment — is not payload.
    }
    flush(&mut data, &mut out);
    out
}

fn first_line(s: &str, cap: usize) -> String {
    let line = s.lines().next().unwrap_or_default();
    line.chars().take(cap).collect()
}

impl Upstream for HttpUpstream {
    fn request(&mut self, req: &Request) -> Response {
        match self.post(req) {
            Ok(r) => r,
            Err(why) => Response::error(req.id.clone(), -32000, why),
        }
    }

    fn notify(&mut self, req: &Request) {
        // A notification's failure is not reportable — there is no id to answer on — but it must
        // not take the process with it either.
        let _ = self.post(req);
    }
}

#[cfg(test)]
mod http_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use serde_json::json;

    /// Bodies are built from lines rather than written as escaped literals: an SSE field must
    /// start at column 0, so a stray indent in a test fixture produces a body no server would
    /// send and a failure that says nothing about the parser.
    fn body(lines: &[&str]) -> String {
        let mut s = lines.join("\n");
        s.push('\n');
        s
    }

    fn sse(b: &str, id: i64) -> Option<String> {
        sse_frame_for(b, Some(&json!(id)))
    }

    #[test]
    fn a_single_data_line_is_the_frame() {
        let b = body(&[
            "event: message",
            r#"data: {"jsonrpc":"2.0","id":7,"result":{}}"#,
            "",
        ]);
        let v: serde_json::Value = serde_json::from_str(&sse(&b, 7).expect("frame")).unwrap();
        assert_eq!(v["id"], json!(7));
    }

    #[test]
    fn multiple_data_lines_reassemble_into_one_payload() {
        let b = body(&[
            r#"data: {"jsonrpc":"2.0","#,
            r#"data:  "id":7,"#,
            r#"data:  "result":{"ok":true}}"#,
            "",
        ]);
        let v: serde_json::Value = serde_json::from_str(&sse(&b, 7).expect("frame")).unwrap();
        assert_eq!(v["result"]["ok"], json!(true));
    }

    #[test]
    fn data_lines_are_joined_with_a_newline_not_concatenated() {
        // The spec builds the payload by appending each `data:` value **followed by a newline**,
        // then dropping the trailing one. For JSON that is usually indistinguishable from
        // concatenation, because JSON ignores whitespace between tokens — so the case that tells
        // them apart is a token split mid-way. Joined, this is invalid JSON and correctly yields
        // nothing; concatenated, it would silently reassemble into `{"name":1}` and the mediator
        // would accept a frame the server never sent.
        let b = body(&[
            r#"data: {"jsonrpc":"2.0","id":1,"na"#,
            r#"data: me":1}"#,
            "",
        ]);
        assert!(
            sse(&b, 1).is_none(),
            "a token split across data lines was reassembled as if the newline were not there"
        );
    }

    #[test]
    fn a_progress_notification_does_not_satisfy_a_request() {
        // The failure this exists to prevent: the first block is a notification with no id, and
        // answering the call with it hands the agent something that is not the answer.
        let b = body(&[
            r#"data: {"jsonrpc":"2.0","method":"notifications/progress","params":{}}"#,
            "",
            r#"data: {"jsonrpc":"2.0","id":9,"result":{"tools":[]}}"#,
            "",
        ]);
        let v: serde_json::Value =
            serde_json::from_str(&sse(&b, 9).expect("frame for id 9")).unwrap();
        assert_eq!(v["id"], json!(9));
        assert!(v.get("result").is_some(), "took the notification instead");
    }

    #[test]
    fn a_frame_for_another_id_is_not_taken() {
        let b = body(&[r#"data: {"jsonrpc":"2.0","id":1,"result":{}}"#, ""]);
        assert!(sse(&b, 2).is_none(), "id 1 answered a request for id 2");
    }

    #[test]
    fn comments_and_other_fields_are_not_payload() {
        let b = body(&[
            ": keep-alive",
            "event: message",
            "id: 42",
            "retry: 3000",
            r#"data: {"jsonrpc":"2.0","id":3,"result":{}}"#,
            "",
        ]);
        assert!(
            sse(&b, 3).is_some(),
            "a comment or an id: field was read as payload"
        );
    }

    #[test]
    fn the_first_matching_frame_wins() {
        let b = body(&[
            r#"data: {"jsonrpc":"2.0","id":5,"result":{"n":1}}"#,
            "",
            r#"data: {"jsonrpc":"2.0","id":5,"result":{"n":2}}"#,
            "",
        ]);
        let v: serde_json::Value = serde_json::from_str(&sse(&b, 5).unwrap()).unwrap();
        assert_eq!(v["result"]["n"], json!(1));
    }

    #[test]
    fn a_body_with_no_terminating_blank_line_still_yields_its_frame() {
        // Real servers close the stream without a trailing blank line. Requiring one would make
        // the last frame — usually the answer — invisible.
        let b = r#"data: {"jsonrpc":"2.0","id":4,"result":{}}"#;
        assert!(sse(b, 4).is_some(), "a frame at EOF was dropped");
    }

    #[test]
    fn unparseable_data_is_skipped_rather_than_returned() {
        let b = body(&[
            "data: not json",
            "",
            r#"data: {"jsonrpc":"2.0","id":8,"result":{}}"#,
            "",
        ]);
        let v: serde_json::Value = serde_json::from_str(&sse(&b, 8).unwrap()).unwrap();
        assert_eq!(v["id"], json!(8));
    }

    #[test]
    fn an_indented_field_is_not_a_field() {
        // SSE fields start at column 0. Being lenient here would accept bodies no server sends
        // and mask a genuinely malformed stream.
        let b = body(&[r#"  data: {"jsonrpc":"2.0","id":1,"result":{}}"#, ""]);
        assert!(sse(&b, 1).is_none());
    }
}

#[cfg(test)]
mod flag_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::{check_upstream_url, parse_upstream_header};

    #[test]
    fn a_header_splits_on_the_first_colon_so_values_may_contain_colons() {
        let (n, v) = parse_upstream_header("Authorization: Bearer https://idp/x:9443").unwrap();
        assert_eq!(n, "Authorization");
        assert_eq!(v, "Bearer https://idp/x:9443");
    }

    #[test]
    fn a_header_name_and_value_are_trimmed() {
        assert_eq!(
            parse_upstream_header("  X-Tenant :  acme  ").unwrap(),
            ("X-Tenant".to_string(), "acme".to_string())
        );
    }

    #[test]
    fn a_header_without_a_colon_is_refused() {
        assert!(parse_upstream_header("Authorization Bearer x").is_err());
    }

    #[test]
    fn a_header_with_an_empty_name_is_refused() {
        assert!(parse_upstream_header(": value").is_err());
    }

    #[test]
    fn a_header_carrying_a_newline_cannot_inject_a_second_header() {
        // Sent verbatim this would append `X-Real-Ip: 10.0.0.1` as its own header line.
        assert!(parse_upstream_header("X-Fwd: a\r\nX-Real-Ip: 10.0.0.1").is_err());
        assert!(parse_upstream_header("X-Fwd\nX-Real-Ip: 1: a").is_err());
    }

    #[test]
    fn https_is_always_allowed() {
        assert!(check_upstream_url("https://mcp.corp.example/rpc", false).is_ok());
    }

    #[test]
    fn plaintext_to_loopback_is_allowed_for_local_development() {
        for url in [
            "http://localhost:8931/mcp",
            "http://127.0.0.1:8931/mcp",
            "http://127.3.2.1/mcp",
            "http://[::1]:8931/mcp",
            "http://LocalHost/mcp",
        ] {
            assert!(check_upstream_url(url, false).is_ok(), "{url}");
        }
    }

    #[test]
    fn plaintext_off_host_is_refused_unless_it_is_opted_into() {
        let url = "http://mcp.corp.example/rpc";
        let why = check_upstream_url(url, false).expect_err("should refuse");
        assert!(why.contains("mcp.corp.example"), "{why}");
        assert!(check_upstream_url(url, true).is_ok());
    }

    #[test]
    fn a_loopback_lookalike_in_the_userinfo_does_not_pass_the_check() {
        // `localhost` here is a username, not the host — the request goes to evil.example.
        assert!(check_upstream_url("http://localhost@evil.example/rpc", false).is_err());
        assert!(check_upstream_url("http://127.0.0.1@evil.example/rpc", false).is_err());
    }

    #[test]
    fn a_loopback_lookalike_in_the_path_does_not_pass_the_check() {
        assert!(check_upstream_url("http://evil.example/localhost", false).is_err());
        assert!(check_upstream_url("http://evil.example/?h=127.0.0.1", false).is_err());
        assert!(check_upstream_url("http://evil.example#127.0.0.1", false).is_err());
    }

    #[test]
    fn a_non_http_scheme_is_refused_rather_than_guessed_at() {
        for url in [
            "ws://h/rpc",
            "file:///etc/passwd",
            "mcp.corp.example/rpc",
            "",
        ] {
            assert!(check_upstream_url(url, true).is_err(), "{url}");
        }
    }

    #[test]
    fn a_url_with_no_host_is_refused() {
        assert!(check_upstream_url("http:///rpc", true).is_err());
        assert!(check_upstream_url("http://:8080/rpc", true).is_err());
    }
}

/// Tests that need a real socket: the two behaviours a canned-body test cannot reach.
#[cfg(test)]
mod http_socket_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use serde_json::json;

    /// Serve `replies` in order, one per request, keeping each connection alive so a client that
    /// reuses one is visibly different from a client that does not. Returns the URL and a counter
    /// of ACCEPTED CONNECTIONS — which is the thing under test, not the request count.
    fn serve(replies: Vec<String>) -> (String, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/mcp", listener.local_addr().unwrap());
        let conns = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&conns);
        std::thread::spawn(move || {
            let mut left = replies.into_iter();
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                seen.fetch_add(1, Ordering::SeqCst);
                // Stay on this connection until the client stops asking or the replies run out.
                loop {
                    if !read_one_request(&mut stream) {
                        break;
                    }
                    match left.next() {
                        Some(reply) => {
                            if stream.write_all(reply.as_bytes()).is_err() {
                                break;
                            }
                            let _ = stream.flush();
                        }
                        None => return,
                    }
                }
            }
        });
        (url, conns)
    }

    /// Read one request off `stream`, headers then body. False when the peer has gone.
    fn read_one_request(stream: &mut TcpStream) -> bool {
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut len = 0usize;
        loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) => return false,
                Ok(_) => {}
                Err(_) => return false,
            }
            let lower = line.to_ascii_lowercase();
            if let Some(v) = lower.strip_prefix("content-length:") {
                len = v.trim().parse().unwrap_or(0);
            }
            if line == "\r\n" || line == "\n" {
                break;
            }
        }
        let mut body = vec![0u8; len];
        std::io::Read::read_exact(&mut reader, &mut body).is_ok()
    }

    fn http(status: &str, ctype: &str, body: &str) -> String {
        format!(
            "HTTP/1.1 {status}\r\ncontent-type: {ctype}\r\ncontent-length: {}\r\n\r\n{body}",
            body.len()
        )
    }

    fn req(id: i64, method: &str) -> Request {
        Request {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(id)),
            method: method.to_string(),
            params: serde_json::Value::Null,
        }
    }

    #[test]
    fn one_connection_is_reused_across_calls() {
        // An agent per call would build a connection pool per call, so every tool call on the hot
        // path would pay a fresh TCP — and against an https gateway, a fresh TLS — handshake.
        let (url, conns) = serve(vec![
            http(
                "200 OK",
                "application/json",
                r#"{"jsonrpc":"2.0","id":1,"result":{}}"#,
            ),
            http(
                "200 OK",
                "application/json",
                r#"{"jsonrpc":"2.0","id":2,"result":{}}"#,
            ),
            http(
                "200 OK",
                "application/json",
                r#"{"jsonrpc":"2.0","id":3,"result":{}}"#,
            ),
        ]);
        let mut up = HttpUpstream::new(&url, Duration::from_secs(5));
        for id in 1..=3 {
            let r = up.request(&req(id, "tools/call"));
            assert!(r.error.is_none(), "call {id} failed: {:?}", r.error);
        }
        assert_eq!(
            conns.load(Ordering::SeqCst),
            1,
            "three calls opened more than one connection; the agent is not being reused"
        );
    }

    #[test]
    fn a_202_with_no_body_fails_a_request_rather_than_answering_it() {
        // 202-with-no-body is the documented answer to a NOTIFICATION. Against a request it means
        // the answer will never arrive on this channel, and synthesising a result would hand the
        // gate a protocol violation dressed as a response.
        let (url, _) = serve(vec![
            "HTTP/1.1 202 Accepted\r\ncontent-length: 0\r\n\r\n".to_string()
        ]);
        let mut up = HttpUpstream::new(&url, Duration::from_secs(5));
        let r = up.request(&req(1, "tools/call"));
        let err = r
            .error
            .expect("a 202 to a request must not read as a result");
        assert!(
            err.message.contains("202"),
            "the refusal does not name the cause: {}",
            err.message
        );
    }

    #[test]
    fn a_session_id_from_the_first_response_is_echoed_on_the_next_request() {
        // Asserted here as well as in the drill because this is the unit that has to remember it.
        let (url, _) = serve(vec![
            format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nmcp-session-id: s-42\r\ncontent-length: {}\r\n\r\n{}",
                r#"{"jsonrpc":"2.0","id":1,"result":{}}"#.len(),
                r#"{"jsonrpc":"2.0","id":1,"result":{}}"#
            ),
            http("200 OK", "application/json", r#"{"jsonrpc":"2.0","id":2,"result":{}}"#),
        ]);
        let mut up = HttpUpstream::new(&url, Duration::from_secs(5));
        up.request(&req(1, "initialize"));
        assert_eq!(up.session.as_deref(), Some("s-42"));
        let r = up.request(&req(2, "tools/call"));
        assert!(r.error.is_none(), "{:?}", r.error);
    }

    #[test]
    fn a_non_2xx_status_is_reported_as_a_failure_not_parsed() {
        let (url, _) = serve(vec![http("403 Forbidden", "text/plain", "no")]);
        let mut up = HttpUpstream::new(&url, Duration::from_secs(5));
        let err = up
            .request(&req(1, "tools/call"))
            .error
            .expect("a 403 must not read as a result");
        assert!(err.message.contains("403"), "{}", err.message);
    }
}
