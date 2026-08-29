//! The C ABI. Every symbol here is called from Lua and none of them may panic across.

use std::ffi::{c_char, c_int};

use warden_connect_gateway::adapter::{
    binding, caller_from_tls, caller_from_xfcc, parse_request_frame, placeholder_callee,
    refusal_frame,
};
use warden_connect_gateway::contracts::Contracts;
use warden_connect_gateway::{BodyAction, BodyMode, Filter, FilterCfg, Verdict};

use crate::config::{Config, Handle, Peer};

// --- verdicts -------------------------------------------------------------
/// Forward the frame unchanged.
pub const WC_FORWARD: c_int = 0;
/// Do not forward. `out` holds the JSON-RPC error frame to return.
pub const WC_REFUSE: c_int = 1;
/// Buffer the response body and hand it to [`wc_on_response_body`].
pub const WC_BUFFER: c_int = 2;
/// Stream the response body through untouched.
pub const WC_SKIP: c_int = 3;
/// Send the buffered body on unchanged.
pub const WC_PASS: c_int = 4;
/// Replace the body with the bytes in `out`.
pub const WC_REWRITE: c_int = 5;

// --- errors ---------------------------------------------------------------
/// A panic was caught at the boundary. Fail closed.
pub const WC_ERR_PANIC: c_int = -1;
/// A null or unusable argument. Fail closed.
pub const WC_ERR_BADARG: c_int = -2;
/// Configuration could not be read or verified. `out` holds the reason.
pub const WC_ERR_CONFIG: c_int = -3;

/// Bytes owned by Rust, to be released with [`wc_out_free`].
///
/// `code` is the `WC-*` taxonomy code as an integer — 4002 for `WC-4002` — so the plugin can
/// label a metric without parsing a string. Zero means no code.
#[repr(C)]
pub struct WcOut {
    /// The bytes, or null.
    pub ptr: *mut u8,
    /// How many.
    pub len: usize,
    /// Taxonomy code, or zero.
    pub code: c_int,
}

impl WcOut {
    fn empty() -> WcOut {
        WcOut {
            ptr: std::ptr::null_mut(),
            len: 0,
            code: 0,
        }
    }

    /// Hand a buffer to the caller. Ownership moves across the ABI.
    fn give(bytes: Vec<u8>, code: c_int) -> WcOut {
        let boxed = bytes.into_boxed_slice();
        let len = boxed.len();
        WcOut {
            ptr: Box::into_raw(boxed).cast::<u8>(),
            len,
            code,
        }
    }
}

/// Run `f`, converting a panic into a fail-closed return.
///
/// `AssertUnwindSafe` is honest here rather than a shortcut: the state that could be observed
/// after a panic is a `Filter` that the caller must now drop, and the ABI gives it no way to
/// keep using one after a non-zero return.
fn guard<F: FnOnce() -> c_int>(what: &str, f: F) -> c_int {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(v) => v,
        Err(_) => {
            eprintln!(
                "{}: PANIC in {what} — refusing this call. This is a bug; the worker survives \
                 because the boundary caught it.",
                binding()
            );
            WC_ERR_PANIC
        }
    }
}

/// The same, for an entry point that returns a pointer.
fn guard_ptr<T, F: FnOnce() -> *mut T>(what: &str, f: F) -> *mut T {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(p) => p,
        Err(_) => {
            eprintln!("{}: PANIC in {what} — returning null.", binding());
            std::ptr::null_mut()
        }
    }
}

/// # Safety
/// `ptr` must be null, or valid for `len` bytes.
unsafe fn slice<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    if ptr.is_null() {
        return None;
    }
    Some(std::slice::from_raw_parts(ptr, len))
}

fn write_out(out: *mut WcOut, v: WcOut) {
    if !out.is_null() {
        // SAFETY: checked non-null; the caller owns a WcOut and must not have freed it.
        unsafe { std::ptr::write(out, v) };
    }
}

fn refuse(out: *mut WcOut, code: wc_core::error::Code, detail: &str) -> c_int {
    write_out(
        out,
        WcOut::give(
            refusal_frame(code, detail).into_bytes(),
            c_int::from(i32::from(code.as_u16())),
        ),
    );
    WC_REFUSE
}

/// Where the request arrived from, as the plugin observed it.
///
/// Never derived from configuration: see `Peer::remote`. An absent value is an address that
/// matches no trusted origin, which is a refusal, not loopback.
fn origin_of(remote: Option<&str>) -> wc_mediator::peer::Origin {
    match remote {
        Some(r) => match r.strip_prefix("unix:") {
            Some(path) => wc_mediator::peer::Origin::UnixSocket {
                path: path.to_string(),
            },
            None => wc_mediator::peer::Origin::Tcp {
                addr: r.to_string(),
            },
        },
        None => wc_mediator::peer::Origin::Tcp {
            addr: String::new(),
        },
    }
}

/// What to call a frame that is not a tool call, so a record always names something.
fn method_label(method: &str) -> String {
    if method.is_empty() {
        "<no method>".to_string()
    } else {
        method.to_string()
    }
}

/// One stream. Never shared between requests.
pub struct WcStream {
    filter: Filter,
    /// The trail, and what this connection's terms say about a lost record. Carried on the
    /// stream because `Decision` needs the connection's identity, and this is where it is known.
    evidence: Option<std::sync::Arc<wc_mediator::evidence::FileSink>>,
    delivery: Option<wc_mediator::evidence::Delivery>,
    cid: String,
    jti: String,
    caller: String,
    callee: String,
    mode: &'static str,
    /// So a proceeding call can be reported as usage, through the same trait method the Envoy
    /// binding uses. `Cache::mark_used` was called only by the stdio gate, so the plane's
    /// re-certification view saw no traffic through either gateway binding and every contract
    /// enforced at a gateway looked dormant.
    contracts: Option<std::sync::Arc<dyn Contracts>>,
}

impl WcStream {
    /// Append one decision, and say whether the call may still proceed.
    ///
    /// A refusal is recorded before it is returned, and an allow before it is forwarded — under
    /// `delivery = "blocking"` a record that cannot be written is itself a refusal, which is
    /// what the term has always claimed and never done.
    fn note(&self, verdict: &str, code: &str, tool: &str, micros: u64) -> bool {
        let Some(sink) = &self.evidence else {
            return true;
        };
        let d = wc_core::obs::Decision {
            cid: &self.cid,
            decision: verdict,
            code,
            mode: self.mode,
            tool,
            caller: &self.caller,
            callee: &self.callee,
            jti: &self.jti,
            at: crate::now(),
            micros,
        };
        sink.record_or_refuse(&d, self.delivery)
    }
}

// --- lifecycle ------------------------------------------------------------

/// Build the process-wide handle from a JSON configuration.
///
/// Returns null on failure, with the reason in `err`. The plugin must refuse to start: a PEP
/// that comes up misconfigured is a PEP that is not in the path.
///
/// # Safety
/// `cfg_json` must be valid for `len` bytes. `err` must be null or a writable [`WcOut`].
#[no_mangle]
pub unsafe extern "C" fn wc_init(cfg_json: *const u8, len: usize, err: *mut WcOut) -> *mut Handle {
    guard_ptr("wc_init", || {
        // Name this binding before anything shared can emit a diagnostic. The modules in
        // wc-gateway serve more than one binary, and a line that says which one has to say it
        // because that binary set it.
        warden_connect_gateway::adapter::set_binding("wc-kong");
        write_out(err, WcOut::empty());
        let Some(bytes) = slice(cfg_json, len) else {
            write_out(err, WcOut::give(b"null config".to_vec(), 8004));
            return std::ptr::null_mut();
        };
        let cfg: Config = match serde_json::from_slice(bytes) {
            Ok(c) => c,
            Err(e) => {
                write_out(err, WcOut::give(format!("config: {e}").into_bytes(), 8004));
                return std::ptr::null_mut();
            }
        };
        match Handle::open(&cfg) {
            Ok(h) => Box::into_raw(Box::new(h)),
            Err(e) => {
                write_out(err, WcOut::give(e.into_bytes(), 8004));
                std::ptr::null_mut()
            }
        }
    })
}

/// Release a handle. The plugin calls this once, at worker exit.
///
/// # Safety
/// `h` must be a pointer from [`wc_init`] that has not already been freed.
#[no_mangle]
pub unsafe extern "C" fn wc_free(h: *mut Handle) {
    if h.is_null() {
        return;
    }
    let _ = guard("wc_free", || {
        drop(Box::from_raw(h));
        0
    });
}

/// How many contracts verified into the set. Negative on a bad argument.
///
/// # Safety
/// `h` must be a live handle from [`wc_init`].
#[no_mangle]
pub unsafe extern "C" fn wc_contract_count(h: *const Handle) -> c_int {
    if h.is_null() {
        return WC_ERR_BADARG;
    }
    guard("wc_contract_count", || {
        c_int::try_from((*h).contracts.len()).unwrap_or(c_int::MAX)
    })
}

/// The library version, as a NUL-terminated string. Never null, never freed.
#[no_mangle]
pub extern "C" fn wc_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0")
        .as_ptr()
        .cast::<c_char>()
}

/// Build a refusal frame for `code`, for the one case the plugin has to speak for itself.
///
/// A panic is caught after the filter has already failed, so there is no frame to hand back —
/// and the plugin still owes the client an answer. Without this the Lua side would carry a
/// hardcoded JSON string, which is a second refusal format that nothing would keep in step.
/// An unknown code becomes `WC-8004`, because a refusal that cannot name itself is a
/// configuration failure.
///
/// Always returns [`WC_REFUSE`].
///
/// # Safety
/// `detail` must be null, or valid for `len` bytes. `out` must be null or writable.
#[no_mangle]
pub unsafe extern "C" fn wc_refusal(
    code: c_int,
    detail: *const u8,
    len: usize,
    out: *mut WcOut,
) -> c_int {
    let r = guard("wc_refusal", || {
        let c = u16::try_from(code)
            .ok()
            .and_then(wc_core::error::Code::new)
            .unwrap_or(wc_core::error::Code::CONFIG_INVALID);
        let d = slice(detail, len)
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .unwrap_or_else(|| c.summary().to_string());
        refuse(out, c, &d)
    });
    // Even a panic inside the refusal builder must not become "forward".
    if r == WC_REFUSE {
        r
    } else {
        WC_REFUSE
    }
}

/// Release bytes handed out by any call here. Idempotent; safe on a zeroed [`WcOut`].
///
/// # Safety
/// `out` must be null, or a [`WcOut`] this library filled and that has not already been freed.
#[no_mangle]
pub unsafe extern "C" fn wc_out_free(out: *mut WcOut) {
    if out.is_null() {
        return;
    }
    let _ = guard("wc_out_free", || {
        let o = &mut *out;
        if !o.ptr.is_null() && o.len > 0 {
            drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(
                o.ptr, o.len,
            )));
        }
        o.ptr = std::ptr::null_mut();
        o.len = 0;
        o.code = 0;
        0
    });
}

// --- per stream -----------------------------------------------------------

/// Open a stream for one request. Never returns null for "no contract" — a stream with no
/// contract refuses every frame, which is a verdict, not an error.
///
/// # Safety
/// `h` must be live; `peer_json` valid for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn wc_stream_new(
    h: *const Handle,
    peer_json: *const u8,
    len: usize,
    err: *mut WcOut,
) -> *mut WcStream {
    guard_ptr("wc_stream_new", || {
        write_out(err, WcOut::empty());
        if h.is_null() {
            write_out(err, WcOut::give(b"null handle".to_vec(), 8004));
            return std::ptr::null_mut();
        }
        let Some(bytes) = slice(peer_json, len) else {
            write_out(err, WcOut::give(b"null peer".to_vec(), 8004));
            return std::ptr::null_mut();
        };
        let peer: Peer = match serde_json::from_slice(bytes) {
            Ok(p) => p,
            Err(e) => {
                write_out(err, WcOut::give(format!("peer: {e}").into_bytes(), 8004));
                return std::ptr::null_mut();
            }
        };
        let handle = &*h;

        let table = handle.routes.table();
        let callee = table
            .lookup(peer.service.as_deref(), peer.route.as_deref())
            .cloned();
        if callee.is_none() {
            eprintln!(
                "{}: no callee for service={:?} route={:?}. An unmapped route refuses every \
                 frame WC-4001 — add it to routes.toml",
                binding(),
                peer.service,
                peer.route
            );
        }

        // Identity from evidence, by the source the operator declared. Never both: falling
        // back would let whoever can suppress one source choose the other.
        let bound = callee.clone().unwrap_or_else(placeholder_callee);
        let caller = match handle.identity {
            crate::config::IdentitySource::Tls => caller_from_tls(
                peer.tls_verify.as_deref(),
                peer.cert_pem.as_deref(),
                peer.remote.as_deref(),
                &bound,
            ),
            crate::config::IdentitySource::Xfcc => {
                let origin = origin_of(peer.remote.as_deref());
                caller_from_xfcc(peer.xfcc.as_deref(), &handle.mesh, &origin, &bound)
            }
        };

        let resolved = callee
            .as_ref()
            .and_then(|c| handle.contracts.resolve(caller.as_deref(), c.as_str()));
        let ceilings = resolved
            .as_ref()
            .map(|r| handle.ceilings.for_contract(r.admitted.jti.as_str()));
        // Captured before `admitted` moves into the filter: a Decision needs the connection's
        // identity, and an absent contract still deserves a record — a refused call is the one
        // an auditor asks about.
        let cid_for_use = resolved
            .as_ref()
            .map(|r| r.admitted.cid.as_str().to_string())
            .unwrap_or_default();
        let (cid, jti, delivery) = match &resolved {
            Some(r) => (
                r.admitted.cid.as_str().to_string(),
                r.admitted.jti.as_str().to_string(),
                Some(wc_mediator::evidence::Delivery::parse(
                    &r.contract.payload.terms.evidence.delivery,
                )),
            ),
            None => (String::new(), String::new(), None),
        };
        let (admitted, contract) = match resolved {
            Some(r) => (Some(r.admitted), Some(r.contract)),
            None => (None, None),
        };

        let bound_id = bound.as_str().to_string();
        let cfg = FilterCfg {
            mode: handle.mode,
            callee: bound,
            pins: handle.pins.clone(),
            pin_max_age: handle.pin_max_age,
        };
        Box::into_raw(Box::new(WcStream {
            filter: Filter::new(admitted, contract, ceilings, crate::now(), &cfg),
            evidence: handle.evidence.clone(),
            delivery,
            cid,
            jti,
            caller: caller.unwrap_or_default(),
            callee: bound_id,
            mode: match handle.mode {
                wc_core::error::Mode::Enforce => "enforce",
                wc_core::error::Mode::Observe => "observe",
            },
            contracts: (!cid_for_use.is_empty()).then(|| handle.contracts_arc()),
        }))
    })
}

/// Release a stream. Drops the concurrency slot it holds.
///
/// # Safety
/// `s` must be a pointer from [`wc_stream_new`] that has not already been freed.
#[no_mangle]
pub unsafe extern "C" fn wc_stream_free(s: *mut WcStream) {
    if s.is_null() {
        return;
    }
    let _ = guard("wc_stream_free", || {
        drop(Box::from_raw(s));
        0
    });
}

/// The request phase. [`WC_FORWARD`], or [`WC_REFUSE`] with the frame to return in `out`.
///
/// # Safety
/// `s` must be live; `body` valid for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn wc_on_request(
    s: *mut WcStream,
    body: *const u8,
    len: usize,
    out: *mut WcOut,
) -> c_int {
    guard("wc_on_request", || {
        write_out(out, WcOut::empty());
        if s.is_null() {
            return WC_ERR_BADARG;
        }
        // A body Kong could not give us is not an empty body. nginx returns nil once the
        // request exceeds client_body_buffer_size, and treating that as "no tool call" would
        // forward exactly the largest requests unchecked.
        let Some(bytes) = slice(body, len) else {
            return refuse(
                out,
                wc_core::error::Code::FRAME_MALFORMED,
                "the request body was not readable — raise client_body_buffer_size, or this \
                 call cannot be checked",
            );
        };
        let started = std::time::Instant::now();
        let (method, params) = match parse_request_frame(bytes) {
            Ok(f) => f,
            Err((code, detail)) => {
                // A frame that would not parse still produced a refusal, and an auditor asking
                // "what did this caller try" needs it in the trail.
                (*s).note("deny", &code.to_string(), "<unparseable frame>", 0);
                return refuse(out, code, detail);
            }
        };
        let tool = wc_mediator::mcp::parse_tool_call(&params)
            .map_or_else(|| method_label(&method), |(t, _)| t);
        let verdict = (*s).filter.on_request(&method, &params);
        let micros = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
        match verdict {
            Verdict::Forward => {
                // Recorded BEFORE forwarding. Under `delivery = "blocking"` a record that
                // cannot be written is itself a refusal — which is what the term has always
                // said and never done.
                if !(*s).note("allow", "WC-0000", &tool, micros) {
                    return refuse(
                        out,
                        wc_core::error::Code::BLOCKING_SINK_UNAVAILABLE,
                        "the decision could not be recorded and this contract's evidence \
                         delivery is blocking",
                    );
                }
                // Reported here rather than at admission: admission says a connection was
                // ESTABLISHED, which is not what a re-certification review is asking. A
                // contract whose consumer connects on every deploy and calls nothing is
                // exactly the one to withdraw.
                let st = &*s;
                if let Some(c) = &st.contracts {
                    if !st.cid.is_empty() {
                        c.mark_used(&st.cid, crate::now());
                    }
                }
                if (*s).filter.is_catalog() {
                    WC_BUFFER
                } else {
                    WC_FORWARD
                }
            }
            Verdict::Refuse { code, detail } => {
                // A refusal is recorded too, and its write failing does not un-refuse it.
                (*s).note("deny", &code.to_string(), &tool, micros);
                refuse(out, code, &detail)
            }
        }
    })
}

/// The response-headers phase. [`WC_BUFFER`], [`WC_SKIP`], or [`WC_REFUSE`].
///
/// # Safety
/// `s` must be live; `ctype` valid for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn wc_on_response_headers(
    s: *mut WcStream,
    ctype: *const u8,
    len: usize,
    out: *mut WcOut,
) -> c_int {
    guard("wc_on_response_headers", || {
        write_out(out, WcOut::empty());
        if s.is_null() {
            return WC_ERR_BADARG;
        }
        let ct = slice(ctype, len)
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .unwrap_or_default();
        match (*s).filter.on_response_headers(&ct) {
            BodyMode::Buffer => WC_BUFFER,
            BodyMode::Skip => WC_SKIP,
            BodyMode::Refuse { code, detail } => refuse(out, code, detail),
        }
    })
}

/// The response-body phase. [`WC_PASS`], [`WC_REWRITE`] with bytes in `out`, or [`WC_REFUSE`].
///
/// # Safety
/// `s` must be live; `body` valid for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn wc_on_response_body(
    s: *mut WcStream,
    body: *const u8,
    len: usize,
    out: *mut WcOut,
) -> c_int {
    guard("wc_on_response_body", || {
        write_out(out, WcOut::empty());
        if s.is_null() {
            return WC_ERR_BADARG;
        }
        let Some(bytes) = slice(body, len) else {
            return refuse(
                out,
                wc_core::error::Code::SURFACE_UNOBTAINABLE,
                "the response body was not readable, so the catalogue could not be filtered",
            );
        };
        match (*s).filter.on_response_body(bytes) {
            BodyAction::Pass => WC_PASS,
            BodyAction::Rewrite(v) => {
                write_out(out, WcOut::give(v.to_string().into_bytes(), 0));
                WC_REWRITE
            }
            BodyAction::Refuse { code, detail } => refuse(out, code, &detail),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The boundary is only a boundary if it catches. This is the whole safety argument for
    /// letting a Rust library be called from LuaJIT, so it is tested directly rather than
    /// inferred from the fact that `catch_unwind` appears in the source.
    #[test]
    fn a_panic_becomes_a_fail_closed_return_not_an_unwind() {
        let r = guard("test", || panic!("boom"));
        assert_eq!(r, WC_ERR_PANIC);
        assert!(r < 0, "every negative return means refuse");
    }

    #[test]
    fn a_panic_in_a_pointer_returning_entry_point_becomes_null() {
        let p: *mut u8 = guard_ptr("test", || panic!("boom"));
        assert!(p.is_null());
    }

    #[test]
    fn guard_passes_a_normal_return_through() {
        assert_eq!(guard("test", || WC_FORWARD), WC_FORWARD);
    }

    #[test]
    fn an_out_buffer_round_trips_and_free_is_idempotent() {
        let mut out = WcOut::give(b"hello".to_vec(), 4002);
        assert_eq!(out.len, 5);
        assert_eq!(out.code, 4002);
        // SAFETY: `out` was filled by this library and has not been freed.
        unsafe {
            let seen = std::slice::from_raw_parts(out.ptr, out.len);
            assert_eq!(seen, b"hello");
            wc_out_free(&raw mut out);
            assert!(out.ptr.is_null(), "free must null the pointer");
            assert_eq!(out.len, 0);
            // Twice, because Lua's error paths will do exactly this.
            wc_out_free(&raw mut out);
            wc_out_free(std::ptr::null_mut());
        }
    }

    #[test]
    fn an_empty_out_is_safe_to_free() {
        let mut out = WcOut::empty();
        // SAFETY: a zeroed WcOut is explicitly documented as safe to free.
        unsafe { wc_out_free(&raw mut out) };
        assert!(out.ptr.is_null());
    }

    #[test]
    fn null_arguments_never_reach_a_dereference() {
        let mut out = WcOut::empty();
        // SAFETY: passing null is the case under test; every entry point checks first.
        unsafe {
            assert_eq!(
                wc_on_request(std::ptr::null_mut(), b"{}".as_ptr(), 2, &raw mut out),
                WC_ERR_BADARG
            );
            assert_eq!(
                wc_on_response_headers(std::ptr::null_mut(), std::ptr::null(), 0, &raw mut out),
                WC_ERR_BADARG
            );
            assert_eq!(
                wc_on_response_body(std::ptr::null_mut(), std::ptr::null(), 0, &raw mut out),
                WC_ERR_BADARG
            );
            assert_eq!(wc_contract_count(std::ptr::null()), WC_ERR_BADARG);
            // These must simply not crash.
            wc_free(std::ptr::null_mut());
            wc_stream_free(std::ptr::null_mut());
        }
    }

    #[test]
    fn version_is_a_nul_terminated_string() {
        let p = wc_version();
        assert!(!p.is_null());
        // SAFETY: the pointer is to a 'static concat! ending in a NUL byte.
        let s = unsafe { std::ffi::CStr::from_ptr(p) }
            .to_str()
            .expect("utf8");
        assert_eq!(s, env!("CARGO_PKG_VERSION"));
    }
}
