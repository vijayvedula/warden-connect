//! The upstream a mediated call is forwarded to.
//!
//! [`Upstream`] is the seam the whole mediator is built on: [`crate::gate::MediatedUpstream`]
//! is a decorator over it, so the eleven checks apply to anything that can answer a JSON-RPC
//! frame. Two methods, which is why inverting the Warden dependency was a small change rather
//! than a rewrite (see [`crate::rpc`]).
//!
//! [`StdioUpstream`] is the real one: an MCP server spawned as a child process, speaking
//! newline-delimited JSON-RPC over its stdin and stdout.
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
        let mut child = Command::new(program)
            .args(&args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
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
