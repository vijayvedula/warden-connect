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

use crate::mcp::{parse_tool_call, tool_error_result};
use crate::rpc::{Request, Response};
use crate::upstream::Upstream;

use wc_core::canon::{self, Limits, SurfaceKind};
use wc_core::contract::{AdmitCtx, Admitted, PeerIdentity, SameTrustLevel, ZoneRule};
use wc_core::error::{Code, Mode, WcError};
use wc_core::model::Pin;

use crate::cache::Cache;
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
    /// Where per-decision lines and data-plane metrics go (P1 #11).
    ///
    /// `Arc` because one `Telemetry` serves every connection this mediator handles — the
    /// counters are estate-wide and a per-connection registry would answer "how many
    /// denials" with "however many this one connection had".
    pub telemetry: Arc<crate::obs::Telemetry>,
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
            telemetry: Arc::new(crate::obs::Telemetry::default()),
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
    /// Admitted, and then the contract stopped being in force: revoked, withdrawn
    /// from the published set, or replaced by a different artifact.
    ///
    /// Distinct from [`State::Denied`] because this connection *was* legitimate and the
    /// operator needs the two apart — "never admitted" and "contained mid-session" are
    /// different incidents. Terminal for the same reason `Denied` is: containment does not
    /// un-happen because the agent asked again. If a contract is reinstated, the session
    /// that was cut reconnects.
    Contained(Code, String),
    /// There is no contract for this pair and this mediator is observing, so the
    /// traffic passes and the absence is the finding (§8.5 UC-08).
    ///
    /// This is the shadow case, and it is deliberately narrow: only an *absent*
    /// contract lands here. A contract that resolves and then fails a closed check
    /// — revoked, pin mismatch, zone crossing — is a different fact from no
    /// contract at all, and the taxonomy closes on those in both modes.
    Observed(Code, String),
}

/// Something the mediator would have refused had it been enforcing.
///
/// Observe mode is not a lenient enforcement mode; it is a deployment where the
/// mediator has no mandate to gate. The findings are its entire output.
#[derive(Debug, Clone)]
pub struct Finding {
    /// The code that would have been returned in enforce mode.
    pub code: Code,
    /// Why.
    pub detail: String,
    /// The tool, when the finding is about one call rather than the connection.
    pub tool: Option<String>,
    /// Whether the traffic went through anyway.
    ///
    /// The pair (code, allowed) is the whole story: the same code means "this was
    /// wrong and I stopped it" when enforcing and "this was wrong and I let it
    /// through" when observing. A finding that recorded only the code would leave a
    /// reader unable to tell those apart, which is the difference between an
    /// incident and an inventory.
    pub allowed: bool,
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
    /// What was wrong with this connection, in both modes. Each carries whether the
    /// traffic was stopped, so the same list serves the observe-mode inventory and
    /// the enforce-mode incident.
    pub findings: Vec<Finding>,
    /// Calls forwarded.
    pub forwarded: u64,
}

impl ConnectionLog {
    /// Whether this connection ran without a contract. True only in observe mode;
    /// in enforce the connection would have been refused instead.
    #[must_use]
    pub fn is_shadow(&self) -> bool {
        self.findings
            .iter()
            .any(|f| f.code == Code::NO_CONTRACT && f.allowed)
    }
}

/// The decorator: wraps the real upstream so the connection is verified, the
/// catalogue is filtered, and ceilings are applied.
pub struct MediatedUpstream {
    inner: Box<dyn Upstream + Send>,
    cache: Arc<Cache>,
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
            cfg,
            state: State::New,
            log: ConnectionLog::default(),
            next_id: 100_000,
        }
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
        // Every refusal produces one line. This is the stream P1 #11 said did not exist,
        // and the reason it has to be here rather than in `deny` is that `deny` records
        // only the *transition* — the second and hundredth refused call on a dead
        // connection are the ones an operator is watching, and they never reach `deny`.
        self.emit(
            crate::obs::Outcome::Deny,
            Some(code),
            parse_tool_call(&req.params).map(|(n, _)| n).as_deref(),
        );
        Response::error_with_data(
            req.id.clone(),
            RPC_BLOCKED,
            format!("BLOCKED by warden-connect: {code} {detail}"),
            json!({
                "code": code.to_string(),
                "summary": code.summary(),
                "cid": self.log.cid,
            }),
        )
    }

    /// Refuse the connection, and record why.
    ///
    /// The recording is not decoration. UC-08 asks for the enforce-mode refusal to
    /// be *raised as an incident*, and a refusal that leaves nothing in the
    /// connection log cannot be. The subsequent refusals on the same connection are
    /// consequences of this one, so only the transition is recorded — a denied
    /// connection that retries a hundred times is one finding, not a hundred.
    fn deny(&mut self, code: Code, detail: &str) {
        self.state = State::Denied(code, detail.to_string());
        self.log.findings.push(Finding {
            code,
            detail: detail.to_string(),
            tool: None,
            allowed: false,
        });
    }

    /// No contract, and nothing to do about it here: record the finding and let the
    /// traffic through untouched.
    ///
    /// The forwarding is the point. P0 ships the mediator in observe mode onto live
    /// paths to find out what is already talking to what, and its exit criterion is
    /// *zero behaviour change measured on the proxy path* (§8.16). A mediator that
    /// refused uncontracted traffic while calling itself an observer would be the
    /// worst version of this: it reads as configured, and it breaks production.
    fn observe(
        &mut self,
        req: &Request,
        code: Code,
        detail: &str,
        tool: Option<String>,
    ) -> Response {
        self.emit(crate::obs::Outcome::Record, Some(code), tool.as_deref());
        self.log.findings.push(Finding {
            code,
            detail: detail.to_string(),
            tool,
            allowed: true,
        });
        self.log.forwarded += 1;
        self.inner.request(req)
    }

    /// Write one decision to the telemetry.
    ///
    /// Reads the peers and mode off the configuration rather than taking them as
    /// arguments, so a new call site cannot pass the wrong ones — the whole value of the
    /// `mode` field is that it distinguishes an observe deployment from an estate under
    /// attack, and a call site that got it backwards would invert exactly that.
    fn emit(&self, outcome: crate::obs::Outcome, code: Option<Code>, tool: Option<&str>) {
        let jti = match &self.state {
            State::Live { admitted, .. } => admitted.jti.as_str(),
            _ => "",
        };
        self.cfg.telemetry.record(
            self.log.cid.as_deref().unwrap_or(""),
            outcome,
            code,
            self.cfg.mode,
            tool.unwrap_or(""),
            self.cfg.peer.caller.as_str(),
            self.cfg.peer.callee.as_str(),
            jti,
            (self.cfg.now)(),
            0,
        );
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

        // Timed, because §8.14 declares `wc_verify_duration_seconds{path}` and nothing was
        // observing it — the family was declared, documented, and never populated. This is
        // the connection-establishment cost §7.10 bounds at p99 < 5 ms.
        let started = std::time::Instant::now();
        let contract =
            match self
                .cache
                .resolve(cid.as_deref(), &self.cfg.peer.caller, &self.cfg.peer.callee)
            {
                Ok(c) => c,
                Err(e) => {
                    // Only an *absent* contract softens. `resolve` also refuses when
                    // the revocation set cannot be relied on, and that is a
                    // containment failure rather than a shadow connection — softening
                    // it would mean an observe-mode mediator keeps serving a party
                    // somebody has revoked.
                    if self.cfg.mode == Mode::Observe && e.code() == Code::NO_CONTRACT {
                        self.state = State::Observed(e.code(), e.detail().to_string());
                        self.log.findings.push(Finding {
                            code: e.code(),
                            detail: e.detail().to_string(),
                            tool: None,
                            allowed: true,
                        });
                        return response;
                    }
                    self.deny(e.code(), e.detail());
                    return self.blocked(req, e.code(), e.detail());
                }
            };
        self.log.cid = Some(contract.payload.cid.as_str().to_string());
        // `warm`: the contract came from the installed snapshot, which is every resolve the
        // mediator does — it verifies signatures once at install time, not per connection.
        // A `cold` path would mean rebuilding the key set, which only `Snapshot::build` does.
        self.cfg
            .telemetry
            .verified(true, started.elapsed().as_secs_f64());

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
                self.deny(e.code(), e.detail());
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
            // Not an empty catalogue: a contained connection is over, and answering
            // `tools/list` with `[]` would read to the agent as a server that has nothing
            // rather than a connection somebody cut.
            State::Contained(code, detail) => return self.blocked(req, *code, detail),
            State::Observed(code, detail) => {
                let (code, detail) = (*code, detail.clone());
                // Unfiltered on purpose: with no contract there is no allowlist to
                // filter against, and an empty catalogue is a behaviour change.
                return self.observe(req, code, &detail, None);
            }
            State::New => {
                if self.cfg.mode == Mode::Observe {
                    return self.observe(
                        req,
                        Code::NO_CONTRACT,
                        "catalogue requested before any handshake",
                        None,
                    );
                }
                return self.blocked(
                    req,
                    Code::NO_CONTRACT,
                    "no connection: call initialize first",
                );
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
                            self.deny(e.code(), e.detail());
                            self.log
                                .denials
                                .push((catalog.method().to_string(), e.code()));
                            return self.blocked(req, e.code(), e.detail());
                        }
                    }
                    Err(e) => {
                        // A surface we cannot canonicalise cannot be compared to a
                        // pin, so it cannot be trusted.
                        self.deny(e.code(), e.detail());
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
        // §8.14's `wc_filter_tools{state}` and `wc_filter_failclosed_total`. The
        // fail-closed counter is the one that matters most and is the easiest to miss: an
        // unparseable upstream response becomes an *empty* catalogue, so the agent sees no
        // tools and reports "the server has nothing", which reads as a broken upstream
        // rather than as this mediator refusing to guess.
        self.cfg
            .telemetry
            .filtered(stat.exposed as u64, stat.hidden as u64, stat.failed_closed);
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

    /// Re-check a live connection against the current cache, before every method.
    ///
    /// The containment seam. Until this existed, `initialize` resolved the contract once and
    /// every later call used the `Admitted` it produced — so a revoked, withdrawn or replaced
    /// contract went on being served to expiry. `scripts/rotation-drill.sh` measured it from
    /// both directions: retiring the issuer key changed nothing, and quarantining the callee
    /// changed nothing while the mediator's own refresh log read `1 rejected`. It *knew*, and
    /// served anyway, because knowing lived in the cache and the hot path never asked.
    ///
    /// Called from [`Upstream::request`] rather than from each handler on purpose. Three call
    /// sites would be three chances to forget one, and the method somebody forgot would be
    /// the uncontained one — this codebase's recurring defect is a control that is configured
    /// and unreached (`docs/threat-model.md` Part 1).
    ///
    /// Cheap enough to belong here: no signature is verified, because the snapshot was
    /// verified once at install. See [`Cache::still_in_force`].
    fn revalidate(&mut self) {
        let State::Live { admitted, .. } = &self.state else {
            return;
        };
        let (cid, jti) = (
            admitted.cid.as_str().to_string(),
            admitted.jti.as_str().to_string(),
        );
        let Err(e) =
            self.cache
                .still_in_force(&cid, &jti, &self.cfg.peer.caller, &self.cfg.peer.callee)
        else {
            // Still in force, and this call is about to proceed — so the connection is in use
            // (W10). Recorded here rather than at admission because admission happens once per
            // session and tells you a connection was *established*, which is not the question a
            // re-certification review is asking. A contract whose consumer connects on every
            // deploy and calls nothing is exactly the one to withdraw.
            self.cache.mark_used(&cid, (self.cfg.now)());
            return;
        };

        // Mode is decided by the taxonomy, not by a list of codes kept here. `WC-4001` and
        // `WC-3105` are both `Closed`, so containment lands in observe mode too — and if a
        // future code out of `resolve` is `ClosedUnlessObserve`, this softens it without
        // anybody having to remember to come back and edit a condition.
        //
        // Observe mode closing here is deliberate and worth defending, because the first
        // version of this softened an absent contract to match `on_initialize`. That was
        // wrong. `on_initialize` overrides the taxonomy for one narrow reason — UC-08 shadow
        // detection, an *uncontracted pair* the mediator is only there to discover — and
        // §8.16's "zero behaviour change" criterion is measured on exactly that case. A
        // connection that was admitted under a contract and then lost it is not an
        // uncontracted pair; it is a withdrawal. Softening it would mean an operator who
        // quarantines a party in an observe-mode estate gets nothing at all, which is the
        // defect class this whole exercise is about.
        if !e.denies_in(self.cfg.mode) {
            // Once per connection. `revalidate` runs on every method, and a finding pushed
            // each time would turn one fact into a log flood that buries the rest.
            if !self.log.findings.iter().any(|f| f.code == e.code()) {
                self.log.findings.push(Finding {
                    code: e.code(),
                    detail: e.detail().to_string(),
                    tool: None,
                    allowed: true,
                });
            }
            return;
        }

        self.state = State::Contained(e.code(), e.detail().to_string());
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
            // `tool_denial` and not `blocked`, matching how an expired contract comes out:
            // the contract stopped being valid under a call that was otherwise well formed,
            // so the agent should see a failed call rather than a broken transport.
            State::Contained(code, detail) => {
                let (code, detail) = (*code, detail.clone());
                return self.tool_denial(req, code, &detail);
            }
            State::Observed(code, detail) => {
                let (code, detail) = (*code, detail.clone());
                let tool = parse_tool_call(&req.params).map(|(n, _)| n);
                return self.observe(req, code, &detail, tool);
            }
            State::New => {
                if self.cfg.mode == Mode::Observe {
                    let tool = parse_tool_call(&req.params).map(|(n, _)| n);
                    return self.observe(req, Code::NO_CONTRACT, "call before any handshake", tool);
                }
                return self.blocked(
                    req,
                    Code::NO_CONTRACT,
                    "no connection: call initialize first",
                );
            }
        };
        let _ = cid;

        // Skipping discovery must not skip verification: fetch the catalogue
        // ourselves and check the pin before anything is forwarded.
        if needs_pin {
            if let Err(e) = self.verify_pin_lazily() {
                self.deny(e.code(), e.detail());
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
            State::Contained(code, detail) => {
                let (code, detail) = (*code, detail.clone());
                return self.tool_denial(req, code, &detail);
            }
            State::Observed(code, detail) => {
                let (code, detail) = (*code, detail.clone());
                return self.observe(req, code, &detail, Some(tool));
            }
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

        // Rate, concurrency and spend ceilings used to be enforced here. They are gone:
        // counters live in one process, so the number an owner wrote was never the number in
        // force, and a proxy is where traffic shaping belongs. `connect offer lint` refuses a
        // term that claims otherwise.

        // The allow path. Timed around the upstream call so `latency_us` is the cost of
        // the whole mediated hop, which is the number §7.10's per-call budget is about.
        let started = std::time::Instant::now();
        self.log.forwarded += 1;
        let response = self.inner.request(req);
        self.cfg.telemetry.record(
            self.log.cid.as_deref().unwrap_or(""),
            crate::obs::Outcome::Allow,
            None,
            self.cfg.mode,
            &tool,
            self.cfg.peer.caller.as_str(),
            self.cfg.peer.callee.as_str(),
            admitted.jti.as_str(),
            now,
            started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64,
        );
        response
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
        // A second refusal exit, distinct from `blocked` because a refused *call* is a
        // JSON-RPC result carrying an error rather than a protocol error. It needs its own
        // emit for exactly that reason: this is where an expired contract, an uncontracted
        // tool and a ceiling breach come out, which is most of what an operator cares
        // about, and hooking only `blocked` would have logged none of them.
        self.emit(
            crate::obs::Outcome::Deny,
            Some(code),
            parse_tool_call(&req.params).map(|(n, _)| n).as_deref(),
        );
        if matches!(
            code,
            Code::RATE_CEILING | Code::SPEND_CEILING | Code::CONCURRENCY_CEILING
        ) {
            self.cfg.telemetry.ceiling_breach(match code {
                Code::RATE_CEILING => "rate",
                Code::SPEND_CEILING => "spend",
                _ => "concurrency",
            });
        }
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
        // Before anything else, and for every method: is the contract still in force?
        // One seam, so no handler can be the one that forgot to ask.
        self.revalidate();

        match req.method.as_str() {
            "initialize" => self.on_initialize(req),
            "tools/call" => self.on_tool_call(req),
            method => match Catalog::from_method(method) {
                Some(catalog) => self.on_catalog(req, catalog),
                // Anything else passes through, but only on a live connection: an
                // unrecognised method must not be a way to reach an upstream the
                // agent has no contract for.
                None => match &self.state {
                    State::Live { .. } | State::Observed(_, _) => self.inner.request(req),
                    State::Denied(code, detail) | State::Contained(code, detail) => {
                        self.blocked(req, *code, detail)
                    }
                    State::New => self.inner.request(req),
                },
            },
        }
    }

    fn notify(&mut self, req: &Request) {
        // Notifications carry no id and expect no response, so there is nothing to
        // filter — but a denied connection must not be able to send them, and neither
        // must a contained one. A notification still reaches the upstream, so leaving this
        // open would mean containment stopped the calls and not the traffic.
        self.revalidate();
        if matches!(self.state, State::Denied(_, _) | State::Contained(_, _)) {
            return;
        }
        self.inner.notify(req);
    }
}
