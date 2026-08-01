//! The inline mediator, as an `Upstream` decorator (`docs/08-lld.md` §8.6.1).
//!
//! Warden core routes `initialize`, every list method and every allowed
//! `tools/call` through its public `Upstream` trait, so the mediator needs **no
//! change to Warden core**: it wraps the real upstream and sees all three.
//!
//! # Where each check lands, and why
//!
//! MCP's `initialize` does not return the tool list, so the pinned-surface
//! comparison (check 8) genuinely cannot happen there. The sequence is therefore:
//!
//! | Wire event | Checks |
//! |---|---|
//! | `initialize` | resolve the contract; 1–7, 9–11 |
//! | `tools/list` | 8 against the presented surface, then filter |
//! | `tools/call` | 8 (lazily, if not yet done), then the surface allowlist |
//!
//! That last row matters. An agent that never calls `tools/list` would otherwise
//! skip check 8 entirely, so the first `tools/call` triggers the mediator's **own**
//! `tools/list` against the upstream and verifies the pin before forwarding
//! anything. Skipping discovery must not be a way to skip verification.

use std::collections::BTreeSet;
use std::sync::Arc;

use serde_json::{json, Value};

use warden::jsonrpc::{Request, Response};
use warden::mcp::{parse_tool_call, tool_error_result};
use warden::upstream::Upstream;

use wc_core::canon::{self, Limits, SurfaceKind};
use wc_core::contract::{AdmitCtx, Admitted, PeerIdentity, SameTrustLevel, ZoneRule};
use wc_core::error::{Code, Mode, WcError};
use wc_core::model::Pin;

use crate::cache::Cache;
use crate::ceiling::Ceilings;
use crate::filter::{self, Catalog, FilterStat};

/// JSON-RPC error code for a refused connection. Distinct from a tool error: the
/// connection itself was refused, not the call.
pub const RPC_BLOCKED: i64 = -32001;

/// How the mediator behaves on this connection.
pub struct GateCfg {
    /// This mediator's id; must equal the contract's `aud`.
    pub mediator_id: String,
    /// Enforce or observe.
    pub mode: Mode,
    /// The authenticated peers. Never taken from the request — supplied by the
    /// transport (§8.6.6).
    pub peer: PeerIdentity,
    /// `wcid` from the session token, when it carries one.
    pub token_wcid: Option<String>,
    /// Local zone policy.
    pub zones: Box<dyn ZoneRule + Send + Sync>,
    /// Canonicalisation limits for the presented surface.
    pub limits: Limits,
    /// Wall clock, injected so tests and replays are deterministic.
    pub now: fn() -> u64,
}

impl GateCfg {
    /// A configuration for the common sidecar case: one agent, one upstream,
    /// same-trust-level zones only.
    #[must_use]
    pub fn new(mediator_id: &str, peer: PeerIdentity, now: fn() -> u64) -> GateCfg {
        GateCfg {
            mediator_id: mediator_id.to_string(),
            mode: Mode::Enforce,
            peer,
            token_wcid: None,
            zones: Box::new(SameTrustLevel),
            limits: Limits::default(),
            now,
        }
    }

    /// Switch to observe mode.
    #[must_use]
    pub fn observing(mut self) -> GateCfg {
        self.mode = Mode::Observe;
        self
    }
}

impl std::fmt::Debug for GateCfg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GateCfg")
            .field("mediator_id", &self.mediator_id)
            .field("mode", &self.mode)
            .field("peer", &self.peer)
            .finish_non_exhaustive()
    }
}

/// Where the connection is.
#[derive(Debug)]
enum State {
    /// No `initialize` seen yet.
    New,
    /// Admitted; `pin_verified` records whether check 8 has run.
    Live {
        admitted: Box<Admitted>,
        pin_verified: bool,
    },
    /// Refused. Terminal for this connection — a denied connection does not get
    /// to retry its way in.
    Denied(Code, String),
}

/// What the mediator observed on a connection, for the evidence record.
#[derive(Debug, Default, Clone)]
pub struct ConnectionLog {
    /// The connection id, once resolved.
    pub cid: Option<String>,
    /// Catalogue filtering, per catalogue.
    pub filtered: Vec<(String, FilterStat)>,
    /// Calls refused, with the code.
    pub denials: Vec<(String, Code)>,
    /// Calls forwarded.
    pub forwarded: u64,
}

/// The decorator: wraps the real upstream so the connection is verified, the
/// catalogue is filtered, and ceilings are applied.
pub struct MediatedUpstream {
    inner: Box<dyn Upstream + Send>,
    cache: Arc<Cache>,
    ceilings: Ceilings,
    cfg: GateCfg,
    state: State,
    log: ConnectionLog,
    next_id: i64,
}

impl std::fmt::Debug for MediatedUpstream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MediatedUpstream")
            .field("state", &self.state)
            .field("log", &self.log)
            .finish_non_exhaustive()
    }
}

impl MediatedUpstream {
    /// Wrap an upstream.
    #[must_use]
    pub fn new(inner: Box<dyn Upstream + Send>, cache: Arc<Cache>, cfg: GateCfg) -> Self {
        MediatedUpstream {
            inner,
            cache,
            ceilings: Ceilings::default(),
            cfg,
            state: State::New,
            log: ConnectionLog::default(),
            next_id: 100_000,
        }
    }

    /// Attach ceilings. Without this the contract's terms are recorded but not
    /// enforced, so a deployment that cares about rate or spend must call it.
    #[must_use]
    pub fn with_ceilings(mut self, ceilings: Ceilings) -> Self {
        self.ceilings = ceilings;
        self
    }

    /// What happened on this connection.
    #[must_use]
    pub fn log(&self) -> &ConnectionLog {
        &self.log
    }

    /// The admitted connection, if there is one.
    #[must_use]
    pub fn admitted(&self) -> Option<&Admitted> {
        match &self.state {
            State::Live { admitted, .. } => Some(admitted),
            _ => None,
        }
    }

    fn blocked(&self, req: &Request, code: Code, detail: &str) -> Response {
        Response {
            jsonrpc: "2.0".to_string(),
            id: req.id.clone(),
            result: None,
            error: Some(warden::jsonrpc::RpcError {
                code: RPC_BLOCKED,
                message: format!("BLOCKED by warden-connect: {code} {detail}"),
                data: Some(json!({
                    "code": code.to_string(),
                    "summary": code.summary(),
                    "cid": self.log.cid,
                })),
            }),
        }
    }

    /// `initialize`: resolve the contract and run every check that does not need
    /// the tool list.
    fn on_initialize(&mut self, req: &Request) -> Response {
        // Forward first: a contract is verified against what the callee actually
        // presents, and refusing before the handshake would leave the agent unable
        // to tell a policy refusal from a broken server.
        let response = self.inner.request(req);

        let cid = req
            .params
            .get("_meta")
            .and_then(|m| m.get("warden"))
            .and_then(|w| w.get("cid"))
            .and_then(Value::as_str)
            .map(str::to_string);

        let contract =
            match self
                .cache
                .resolve(cid.as_deref(), &self.cfg.peer.caller, &self.cfg.peer.callee)
            {
                Ok(c) => c,
                Err(e) => {
                    self.state = State::Denied(e.code(), e.detail().to_string());
                    return self.blocked(req, e.code(), e.detail());
                }
            };
        self.log.cid = Some(contract.payload.cid.as_str().to_string());

        let unused = Pin::empty((self.cfg.now)());
        let ctx = AdmitCtx {
            peer: &self.cfg.peer,
            // Unused by `admit_context`; the real comparison happens once the
            // catalogue arrives.
            presented: &unused,
            token_wcid: self.cfg.token_wcid.as_deref(),
            zones: self.cfg.zones.as_ref(),
            mode: self.cfg.mode,
        };

        // Only the context checks here: `initialize` carries no tool list, so the
        // pin comparison is owed and tracked, not skipped (§8.6.1).
        match contract.admit_context(&ctx) {
            Ok(admitted) => {
                self.state = State::Live {
                    admitted: Box::new(admitted),
                    pin_verified: false,
                };
                response
            }
            Err(e) => {
                self.state = State::Denied(e.code(), e.detail().to_string());
                self.blocked(req, e.code(), e.detail())
            }
        }
    }

    /// Verify the presented surface against the contracted digest (check 8).
    fn verify_pin(&mut self, presented: &Pin) -> Result<(), WcError> {
        let State::Live { admitted, .. } = &self.state else {
            return Err(WcError::with_detail(
                Code::NO_CONTRACT,
                "connection is not admitted",
            ));
        };
        let contract = self.cache.resolve(
            Some(admitted.cid.as_str()),
            &self.cfg.peer.caller,
            &self.cfg.peer.callee,
        )?;

        contract.check_pin(presented)?;

        if let State::Live { pin_verified, .. } = &mut self.state {
            *pin_verified = true;
        }
        Ok(())
    }

    /// Canonicalise a `tools/list` result into a pin, as admission would have.
    fn pin_from_catalog(&self, result: &Value) -> Result<Pin, WcError> {
        canon::pin(
            SurfaceKind::McpTools,
            &self.cfg.peer.callee,
            result,
            &self.cfg.limits,
            (self.cfg.now)(),
        )
    }

    /// A catalogue request: verify the pin from what came back, then filter.
    fn on_catalog(&mut self, req: &Request, catalog: Catalog) -> Response {
        let items = match &self.state {
            State::Live { admitted, .. } => permitted_for(admitted, catalog),
            State::Denied(code, detail) => return self.blocked(req, *code, detail),
            State::New => {
                return self.blocked(
                    req,
                    Code::NO_CONTRACT,
                    "no connection: call initialize first",
                )
            }
        };

        let response = self.inner.request(req);

        // The tool catalogue is the presented surface, so this is where check 8
        // runs for real.
        if catalog == Catalog::Tools {
            if let Some(result) = response.result.clone() {
                match self.pin_from_catalog(&result) {
                    Ok(pin) => {
                        if let Err(e) = self.verify_pin(&pin) {
                            self.state = State::Denied(e.code(), e.detail().to_string());
                            self.log
                                .denials
                                .push((catalog.method().to_string(), e.code()));
                            return self.blocked(req, e.code(), e.detail());
                        }
                    }
                    Err(e) => {
                        // A surface we cannot canonicalise cannot be compared to a
                        // pin, so it cannot be trusted.
                        self.state = State::Denied(e.code(), e.detail().to_string());
                        return self.blocked(req, e.code(), e.detail());
                    }
                }
            }
        }

        let mut as_value = match serde_json::to_value(&response) {
            Ok(v) => v,
            Err(_) => {
                // Unrenderable response: fail closed rather than pass it on.
                self.log
                    .denials
                    .push((catalog.method().to_string(), Code::CATALOG_UNFILTERABLE));
                return self.blocked(
                    req,
                    Code::CATALOG_UNFILTERABLE,
                    "upstream response could not be inspected",
                );
            }
        };
        let stat = filter::filter_catalog(catalog, &items, &mut as_value);
        self.log
            .filtered
            .push((catalog.method().to_string(), stat.clone()));

        match serde_json::from_value::<Response>(as_value) {
            Ok(filtered) => filtered,
            Err(_) => {
                self.log
                    .denials
                    .push((catalog.method().to_string(), Code::CATALOG_UNFILTERABLE));
                self.blocked(
                    req,
                    Code::CATALOG_UNFILTERABLE,
                    "filtered response could not be rebuilt",
                )
            }
        }
    }

    /// `tools/call`: verify the pin if it has not been, then apply the allowlist
    /// and the ceilings.
    fn on_tool_call(&mut self, req: &Request) -> Response {
        let (cid, needs_pin) = match &self.state {
            State::Live {
                admitted,
                pin_verified,
            } => (admitted.cid.as_str().to_string(), !*pin_verified),
            State::Denied(code, detail) => return self.blocked(req, *code, detail),
            State::New => {
                return self.blocked(
                    req,
                    Code::NO_CONTRACT,
                    "no connection: call initialize first",
                )
            }
        };
        let _ = cid;

        // Skipping discovery must not skip verification: fetch the catalogue
        // ourselves and check the pin before anything is forwarded.
        if needs_pin {
            if let Err(e) = self.verify_pin_lazily() {
                self.state = State::Denied(e.code(), e.detail().to_string());
                self.log.denials.push((
                    parse_tool_call(&req.params)
                        .map(|(n, _)| n)
                        .unwrap_or_else(|| "<unparsed>".to_string()),
                    e.code(),
                ));
                return self.blocked(req, e.code(), e.detail());
            }
        }

        let Some((tool, _args)) = parse_tool_call(&req.params) else {
            // Warden core also rejects this; refusing here too means a malformed
            // call never reaches the upstream even if core's shape changes.
            self.log
                .denials
                .push(("<malformed>".to_string(), Code::FRAME_MALFORMED));
            return Response::ok(
                req.id.clone(),
                tool_error_result(format!(
                    "BLOCKED by warden-connect: {} malformed tools/call",
                    Code::FRAME_MALFORMED
                )),
            );
        };

        let admitted = match &self.state {
            State::Live { admitted, .. } => admitted.clone(),
            State::Denied(code, detail) => return self.blocked(req, *code, detail),
            State::New => return self.blocked(req, Code::NO_CONTRACT, "no connection"),
        };

        // Expiry is hard: a connection does not outlive its contract.
        let now = (self.cfg.now)();
        if !admitted.is_live(now) {
            self.log
                .denials
                .push((tool.clone(), Code::CONTRACT_EXPIRED));
            return self.tool_denial(req, Code::CONTRACT_EXPIRED, "the contract has expired");
        }

        if !admitted.permits_item(&tool) {
            self.log
                .denials
                .push((tool.clone(), Code::TOOL_UNCONTRACTED));
            return self.tool_denial(
                req,
                Code::TOOL_UNCONTRACTED,
                &format!("{tool:?} is not in the contracted surface"),
            );
        }

        if let Err(e) = self.ceilings.reserve(&admitted.terms, now) {
            self.log.denials.push((tool.clone(), e.code()));
            return self.tool_denial(req, e.code(), e.detail());
        }

        self.log.forwarded += 1;
        self.inner.request(req)
    }

    /// Fetch the catalogue on the mediator's own behalf and verify the pin.
    fn verify_pin_lazily(&mut self) -> Result<(), WcError> {
        self.next_id += 1;
        let probe = Request::new(self.next_id, Catalog::Tools.method(), json!({}));
        let response = self.inner.request(&probe);
        let result = response.result.ok_or_else(|| {
            WcError::with_detail(
                Code::SURFACE_UNOBTAINABLE,
                "upstream returned no tool catalogue, so the pin cannot be verified",
            )
        })?;
        let pin = self.pin_from_catalog(&result)?;
        self.verify_pin(&pin)
    }

    /// A refusal shaped as a tool error, so the agent handles it as a failed call
    /// rather than a transport fault.
    fn tool_denial(&self, req: &Request, code: Code, detail: &str) -> Response {
        Response::ok(
            req.id.clone(),
            tool_error_result(format!("BLOCKED by warden-connect: {code} {detail}")),
        )
    }
}

/// The contracted names that filter a given catalogue.
fn permitted_for(admitted: &Admitted, catalog: Catalog) -> BTreeSet<String> {
    match catalog {
        // Tools and skills share the item set; a skill is a callee-side capability
        // and never appears in `tools/list`.
        Catalog::Tools | Catalog::Prompts => admitted.items.clone(),
        Catalog::Resources => admitted.resources.iter().cloned().collect(),
    }
}

impl Upstream for MediatedUpstream {
    fn request(&mut self, req: &Request) -> Response {
        match req.method.as_str() {
            "initialize" => self.on_initialize(req),
            "tools/call" => self.on_tool_call(req),
            method => match Catalog::from_method(method) {
                Some(catalog) => self.on_catalog(req, catalog),
                // Anything else passes through, but only on a live connection: an
                // unrecognised method must not be a way to reach an upstream the
                // agent has no contract for.
                None => match &self.state {
                    State::Live { .. } => self.inner.request(req),
                    State::Denied(code, detail) => self.blocked(req, *code, detail),
                    State::New => self.inner.request(req),
                },
            },
        }
    }

    fn notify(&mut self, req: &Request) {
        // Notifications carry no id and expect no response, so there is nothing to
        // filter — but a denied connection must not be able to send them.
        if matches!(self.state, State::Denied(_, _)) {
            return;
        }
        self.inner.notify(req);
    }
}
