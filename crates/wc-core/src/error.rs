//! The `WC-*` error code taxonomy and the crate's error type.
//!
//! Every rejection anywhere in warden-connect carries a stable code, a fail
//! direction, and a transport mapping — see `docs/08-lld.md` §8.11. Codes are
//! API: additive only, never renumbered, never reused.
//!
//! # Why a newtype and a table, not a 69-variant enum
//!
//! A [`Code`] is a validated `u16`, and the per-code facts live in one sorted
//! [`CODES`] table. An enum would give exhaustive matching we never want (no
//! caller handles all 70 cases) at the price of three 70-arm matches for
//! `summary` / `http` / `fail_direction`. The cases here are *data*, so they
//! live in a table.
//!
//! What we *do* want the compiler to police is the small stuff: [`Category`]
//! and [`FailDirection`] are enums precisely so that a `match` on them cannot
//! silently miss a case.

use std::fmt;
use std::str::FromStr;

// ---------------------------------------------------------------------------
// Code
// ---------------------------------------------------------------------------

/// A `WC-*` error code, e.g. `WC-3108`.
///
/// Construct via the associated constants ([`Code::PIN_MISMATCH`]) for known
/// codes, or [`Code::new`] / [`FromStr`] when parsing untrusted input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Code(u16);

impl Code {
    // --- WC-10xx admission ---
    /// Workload identity unverifiable.
    pub const IDENTITY_UNVERIFIABLE: Code = Code(1001);
    /// Surface unobtainable at handshake — nothing is pinned on trust.
    pub const SURFACE_UNOBTAINABLE: Code = Code(1002);
    /// Agent-card signature invalid.
    pub const CARD_SIGNATURE_INVALID: Code = Code(1003);
    /// Build provenance unverifiable.
    pub const PROVENANCE_UNVERIFIABLE: Code = Code(1004);
    /// Declared-surface screening returned a block-class finding.
    pub const SCREENING_BLOCKED: Code = Code(1005);
    /// Derived risk tier exceeds the requested ceiling.
    pub const TIER_EXCEEDS_CEILING: Code = Code(1006);
    /// Writing the surface pin failed.
    pub const PIN_WRITE_FAILED: Code = Code(1007);
    /// Named owner missing or unresolvable in the directory.
    pub const OWNER_UNRESOLVABLE: Code = Code(1008);
    /// Declared surface exceeds size, count or depth limits.
    pub const SURFACE_LIMITS_EXCEEDED: Code = Code(1010);

    // --- WC-20xx registry & discovery ---
    /// Entity not found.
    pub const ENTITY_NOT_FOUND: Code = Code(2001);
    /// An entity with this id already exists.
    pub const ENTITY_DUPLICATE: Code = Code(2002);
    /// Illegal lifecycle transition.
    pub const ILLEGAL_TRANSITION: Code = Code(2003);
    /// Entity is quarantined; quarantine is never overridable.
    pub const ENTITY_QUARANTINED: Code = Code(2004);
    /// An identifier is syntactically invalid (entity id, cid, jti, owner, zone).
    pub const MALFORMED_IDENTIFIER: Code = Code(2005);
    /// Unknown zone pair — treated as most restrictive.
    pub const ZONE_PAIR_UNKNOWN: Code = Code(2011);
    /// Discovery throttled (anti-enumeration).
    pub const DISCOVERY_THROTTLED: Code = Code(2020);
    /// Asker is not registered or not attested.
    pub const ASKER_NOT_ATTESTED: Code = Code(2021);

    // --- WC-30xx contract lifecycle ---
    /// Contract not found.
    pub const CONTRACT_NOT_FOUND: Code = Code(3001);
    /// Requested surface is not a subset of the callee's declared surface.
    pub const SURFACE_NOT_SUBSET: Code = Code(3010);
    /// Connection policy denied the request.
    pub const POLICY_DENIED: Code = Code(3011);
    /// A mint-time precondition failed.
    pub const MINT_PRECONDITION_FAILED: Code = Code(3012);
    /// Requested TTL exceeds the zone assurance bar; narrowed.
    pub const TTL_EXCEEDS_ZONE_BAR: Code = Code(3013);
    /// Requested terms would widen a ceiling.
    pub const TERMS_WOULD_WIDEN: Code = Code(3014);
    /// Standing-policy cap reached; escalated to a human.
    pub const STANDING_CAP_REACHED: Code = Code(3015);
    /// Approver lacks the required role.
    pub const APPROVER_ROLE_MISSING: Code = Code(3020);
    /// Approval is stale: the policy version moved under it.
    pub const APPROVAL_STALE: Code = Code(3021);
    /// Dual control not satisfied.
    pub const DUAL_CONTROL_MISSING: Code = Code(3022);
    /// Approval signature invalid.
    pub const APPROVAL_SIGNATURE_INVALID: Code = Code(3023);
    /// Renewal blocked: posture degraded.
    pub const RENEWAL_POSTURE_DEGRADED: Code = Code(3030);
    /// Renewal blocked: re-attestation failed.
    pub const RENEWAL_REATTEST_FAILED: Code = Code(3031);
    /// Contract already revoked or expired.
    pub const CONTRACT_ALREADY_ENDED: Code = Code(3032);

    // --- WC-31xx contract verification (data plane) ---
    /// Non-asymmetric or unsupported `alg`.
    pub const ALG_NOT_ASYMMETRIC: Code = Code(3101);
    /// Signature or issuer chain invalid.
    pub const SIGNATURE_INVALID: Code = Code(3102);
    /// Contract expired or not yet valid.
    pub const CONTRACT_EXPIRED: Code = Code(3103);
    /// `aud` does not match this mediator.
    pub const AUDIENCE_MISMATCH: Code = Code(3104);
    /// Contract, connection or party revoked.
    pub const CONTRACT_REVOKED: Code = Code(3105);
    /// Caller peer identity does not match the contract.
    pub const CALLER_PEER_MISMATCH: Code = Code(3106);
    /// Callee peer identity does not match the contract.
    pub const CALLEE_PEER_MISMATCH: Code = Code(3107);
    /// Presented surface pin does not match the contracted digest.
    pub const PIN_MISMATCH: Code = Code(3108);
    /// Counterparty posture is not `attested`.
    pub const POSTURE_NOT_ATTESTED: Code = Code(3109);
    /// Zone pair not permitted by local policy.
    pub const ZONE_PAIR_FORBIDDEN: Code = Code(3110);
    /// Session token and contract are not bound to the same connection.
    pub const TOKEN_BINDING_MISMATCH: Code = Code(3111);
    /// Unknown contract schema version — reject rather than guess.
    pub const SCHEMA_UNKNOWN: Code = Code(3120);
    /// Contract exceeds the size limit.
    pub const CONTRACT_OVERSIZE: Code = Code(3121);

    // --- WC-40xx mediation ---
    /// No contract available (cache miss with control plane unreachable).
    pub const NO_CONTRACT: Code = Code(4001);
    /// An uncontracted tool was attempted.
    pub const TOOL_UNCONTRACTED: Code = Code(4002);
    /// Call-rate ceiling exceeded.
    pub const RATE_CEILING: Code = Code(4003);
    /// Spend ceiling exceeded.
    pub const SPEND_CEILING: Code = Code(4004);
    /// Concurrency or fan-out ceiling exceeded.
    pub const CONCURRENCY_CEILING: Code = Code(4005);
    /// Egress term violated (data class or jurisdiction).
    pub const EGRESS_TERM_VIOLATED: Code = Code(4006);
    /// Catalogue could not be filtered; an empty list was returned.
    pub const CATALOG_UNFILTERABLE: Code = Code(4007);
    /// Malformed or oversized protocol frame.
    pub const FRAME_MALFORMED: Code = Code(4008);
    /// Peer-identity header presented from an untrusted origin.
    pub const PEER_HEADER_UNTRUSTED: Code = Code(4020);

    // --- WC-50xx posture ---
    /// Re-attestation failed.
    pub const REATTEST_FAILED: Code = Code(5001);
    /// Material drift detected.
    pub const DRIFT_MATERIAL: Code = Code(5002);
    /// Credential expiring or expired.
    pub const CREDENTIAL_EXPIRING: Code = Code(5010);
    /// Blast-radius depth limit reached; result truncated.
    pub const BLAST_DEPTH_TRUNCATED: Code = Code(5030);

    // --- WC-60xx containment ---
    /// Quarantine dual control missing.
    pub const QUARANTINE_DUAL_CONTROL_MISSING: Code = Code(6001);
    /// Revocation feed unwritable — containment cannot be recorded.
    pub const REVOCATION_FEED_UNWRITABLE: Code = Code(6002);
    /// Mediator acknowledgement not received; reported unconfirmed.
    pub const MEDIATOR_ACK_MISSING: Code = Code(6003);
    /// Break-glass request outside policy.
    pub const BREAKGLASS_OUTSIDE_POLICY: Code = Code(6004);

    // --- WC-70xx evidence ---
    /// A blocking evidence sink is unavailable; no issuance.
    pub const BLOCKING_SINK_UNAVAILABLE: Code = Code(7001);
    /// Audit chain append failed.
    pub const CHAIN_APPEND_FAILED: Code = Code(7002);
    /// Chain verification found a break.
    pub const CHAIN_BROKEN: Code = Code(7003);
    /// Export failed.
    pub const EXPORT_FAILED: Code = Code(7010);
    /// External PDP unreachable.
    pub const PDP_UNREACHABLE: Code = Code(7020);

    // --- WC-80xx platform ---
    /// Invalid policy; last-known-good retained.
    pub const POLICY_INVALID: Code = Code(8001);
    /// Unknown tenant or cross-tenant reference.
    pub const TENANT_UNKNOWN: Code = Code(8002);
    /// Store write lock held by another writer.
    pub const STORE_LOCKED: Code = Code(8003);
    /// Configuration invalid at startup; refuse to start.
    pub const CONFIG_INVALID: Code = Code(8004);

    /// The numeric form, e.g. `3108`.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self.0
    }

    /// Wrap a raw number, returning `None` unless it is a code we actually
    /// define. Use when the number came from outside the process — a log line,
    /// an API payload, a config file.
    ///
    /// Returns `Option`, not `Result<_, WcError>`: there is no `WC-*` code
    /// meaning "that isn't a code", and inventing one would be circular.
    #[must_use]
    pub fn new(raw: u16) -> Option<Code> {
        let candidate = Code(raw);
        candidate.spec().map(|_| candidate)
    }

    /// The table row for this code, or `None` if it predates this binary.
    #[must_use]
    pub fn spec(self) -> Option<&'static CodeSpec> {
        CODES
            .binary_search_by_key(&self.0, |s| s.code)
            .ok()
            .and_then(|i| CODES.get(i))
    }

    /// Which family this code belongs to.
    #[must_use]
    pub fn category(self) -> Category {
        Category::of(self)
    }

    /// One-line human summary from the table, or `"unknown code"`.
    #[must_use]
    pub fn summary(self) -> &'static str {
        match self.spec() {
            Some(s) => s.summary,
            None => "unknown code",
        }
    }

    /// How the system behaves when this code is raised. An unknown code fails
    /// closed — the safe direction for something this binary does not
    /// understand.
    #[must_use]
    pub fn fail_direction(self) -> FailDirection {
        self.spec().map_or(FailDirection::Closed, |s| s.fail)
    }

    /// Whether raising this code denies the operation in the given mode.
    #[must_use]
    pub fn denies_in(self, mode: Mode) -> bool {
        match self.fail_direction() {
            FailDirection::Closed => true,
            FailDirection::ClosedUnlessObserve => matches!(mode, Mode::Enforce),
            FailDirection::Degrade | FailDirection::Report => false,
        }
    }
}

impl fmt::Display for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "WC-{:04}", self.0)
    }
}

impl FromStr for Code {
    type Err = ParseCodeError;

    // Note the fully-qualified `std::result::Result`: this module defines its own
    // one-parameter `Result<T>` alias below, which shadows the two-parameter std
    // one for the rest of the file. A real, common Rust papercut — and the reason
    // some codebases name theirs `WcResult<T>` instead.
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        s.strip_prefix("WC-")
            .unwrap_or(s)
            .parse::<u16>()
            .ok()
            .and_then(Code::new)
            .ok_or_else(|| ParseCodeError::new(s))
    }
}

/// Returned when a string isn't a code we know.
///
/// A small, local error type for a small, local failure: not every failure
/// deserves the crate's domain error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseCodeError {
    input: String,
}

impl fmt::Display for ParseCodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "not a warden-connect error code: {:?}", self.input)
    }
}

impl std::error::Error for ParseCodeError {}

impl ParseCodeError {
    /// Build the error, recording what was rejected.
    #[must_use]
    pub fn new(input: impl Into<String>) -> Self {
        ParseCodeError {
            input: input.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// Category, FailDirection, Mode
// ---------------------------------------------------------------------------

/// Code families, by numeric block. An enum, so a `match` over families is
/// checked for you.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Category {
    /// `WC-10xx` — admission pipeline.
    Admission,
    /// `WC-20xx` — registry and discovery.
    Registry,
    /// `WC-30xx` — contract lifecycle (request → mint → renew → revoke).
    ContractLifecycle,
    /// `WC-31xx` — contract verification, in the data plane.
    Verification,
    /// `WC-40xx` — channel mediation.
    Mediation,
    /// `WC-50xx` — continuous posture.
    Posture,
    /// `WC-60xx` — containment and revocation.
    Containment,
    /// `WC-70xx` — evidence and interoperability.
    Evidence,
    /// `WC-80xx` — platform and operations.
    Platform,
}

impl Category {
    /// The family a code belongs to.
    ///
    /// # Panics
    ///
    /// Panics if a code in [`CODES`] falls outside every category range — a
    /// broken internal invariant, not bad input. `table_categories_are_total`
    /// proves it cannot happen for any code we define.
    #[must_use]
    pub fn of(code: Code) -> Category {
        match code.as_u16() {
            1000..=1999 => Category::Admission,
            2000..=2999 => Category::Registry,
            3000..=3099 => Category::ContractLifecycle,
            3100..=3999 => Category::Verification,
            4000..=4999 => Category::Mediation,
            5000..=5999 => Category::Posture,
            6000..=6999 => Category::Containment,
            7000..=7999 => Category::Evidence,
            8000..=8999 => Category::Platform,
            other => unreachable!("WC-{other} is outside every category range"),
        }
    }
}

/// What happens to the operation when a code is raised.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FailDirection {
    /// Always denied, in every mode. Quarantine, revocation, feed integrity.
    Closed,
    /// Denied in enforce mode; recorded as a finding in observe mode.
    ClosedUnlessObserve,
    /// Not denied: state or posture degrades instead (no renewal, suspension).
    Degrade,
    /// Not denied: reported to the caller (truncated, narrowed, unconfirmed).
    Report,
}

/// Enforcement mode. Lives here for now; it moves to `model` once the registry
/// needs it too.
///
/// An enum and not a `bool`: `denies_in(Mode::Observe)` reads as what it means,
/// where `denies_in(true)` would be a coin flip at every call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Mode {
    /// Deny on failure.
    Enforce,
    /// Allow and record a finding, where the code permits it.
    Observe,
}

// ---------------------------------------------------------------------------
// The table
// ---------------------------------------------------------------------------

/// One row of the code table: the facts §8.11 records about a code.
#[derive(Debug, Clone, Copy)]
pub struct CodeSpec {
    /// Numeric code.
    pub code: u16,
    /// Fail direction.
    pub fail: FailDirection,
    /// HTTP status for the control-plane API, where one applies.
    pub http: Option<u16>,
    /// JSON-RPC error code for the data plane, where one applies.
    /// `-32001` is warden-connect's "blocked" code; `-32600` is invalid request.
    pub rpc: Option<i32>,
    /// One-line human summary.
    pub summary: &'static str,
}

use FailDirection::{Closed, ClosedUnlessObserve, Degrade, Report};

/// Every code, **sorted by `code`** — [`Code::spec`] binary-searches this, and
/// `table_is_sorted_and_unique` fails the build if the order ever slips.
#[rustfmt::skip]
pub static CODES: &[CodeSpec] = &[
    // --- admission ---
    spec(1001, ClosedUnlessObserve, Some(422), None, "workload identity unverifiable"),
    spec(1002, Closed, Some(424), None, "surface unobtainable at handshake"),
    spec(1003, ClosedUnlessObserve, Some(422), None, "agent-card signature invalid"),
    spec(1004, ClosedUnlessObserve, Some(422), None, "build provenance unverifiable"),
    spec(1005, Closed, Some(422), None, "screening block-class finding"),
    spec(1006, Closed, Some(409), None, "derived tier exceeds requested ceiling"),
    spec(1007, Closed, Some(500), None, "pin write failed"),
    spec(1008, Closed, Some(422), None, "owner missing or unresolvable"),
    spec(1010, Closed, Some(413), None, "surface exceeds size, count or depth limits"),
    // --- registry & discovery ---
    spec(2001, Report, Some(404), None, "entity not found"),
    spec(2002, Report, Some(409), None, "duplicate entity id"),
    spec(2003, Closed, Some(409), None, "illegal lifecycle transition"),
    spec(2004, Closed, Some(403), None, "entity quarantined"),
    spec(2005, Closed, Some(422), None, "malformed identifier"),
    spec(2011, Closed, Some(403), None, "unknown zone pair, treated as most restrictive"),
    spec(2020, Report, Some(200), None, "discovery throttled"),
    spec(2021, ClosedUnlessObserve, Some(200), None, "asker not registered or not attested"),
    // --- contract lifecycle ---
    spec(3001, Report, Some(404), None, "contract not found"),
    spec(3010, Closed, Some(422), None, "requested surface not a subset of declared surface"),
    spec(3011, Closed, Some(403), None, "connection policy denied"),
    spec(3012, Closed, Some(409), None, "mint precondition failed"),
    spec(3013, Report, Some(200), None, "ttl exceeds zone bar, narrowed"),
    spec(3014, Closed, Some(422), None, "terms would widen a ceiling"),
    spec(3015, Closed, Some(202), None, "standing-policy cap reached, escalated to human"),
    spec(3020, Closed, Some(403), None, "approver lacks required role"),
    spec(3021, Closed, Some(409), None, "approval stale, policy version moved"),
    spec(3022, Closed, Some(403), None, "dual control not satisfied"),
    spec(3023, Closed, Some(401), None, "approval signature invalid"),
    spec(3030, Closed, Some(409), None, "renewal blocked, posture degraded"),
    spec(3031, Closed, Some(409), None, "renewal blocked, re-attestation failed"),
    spec(3032, Report, Some(410), None, "contract already revoked or expired"),
    // --- contract verification ---
    spec(3101, Closed, None, Some(-32001), "alg not asymmetric"),
    spec(3102, Closed, None, Some(-32001), "signature or issuer chain invalid"),
    spec(3103, Closed, None, Some(-32001), "contract expired or not yet valid"),
    spec(3104, Closed, None, Some(-32001), "audience is not this mediator"),
    spec(3105, Closed, None, Some(-32001), "contract, connection or party revoked"),
    spec(3106, Closed, None, Some(-32001), "caller peer identity mismatch"),
    spec(3107, Closed, None, Some(-32001), "callee peer identity mismatch"),
    spec(3108, Closed, None, Some(-32001), "surface pin mismatch"),
    spec(3109, ClosedUnlessObserve, None, Some(-32001), "posture not attested"),
    spec(3110, Closed, None, Some(-32001), "zone pair not permitted locally"),
    spec(3111, Closed, None, Some(-32001), "token and contract binding mismatch"),
    spec(3120, Closed, None, Some(-32001), "unknown contract schema version"),
    spec(3121, Closed, None, Some(-32001), "contract exceeds size limit"),
    // --- mediation ---
    spec(4001, Closed, None, Some(-32001), "no contract available"),
    spec(4002, Closed, None, None, "uncontracted tool attempted"),
    spec(4003, Closed, None, None, "rate ceiling exceeded"),
    spec(4004, Closed, None, None, "spend ceiling exceeded"),
    spec(4005, Closed, None, None, "concurrency or fan-out ceiling exceeded"),
    spec(4006, Closed, None, None, "egress term violated"),
    spec(4007, Closed, Some(200), None, "catalogue unfilterable, empty list returned"),
    spec(4008, Closed, None, Some(-32600), "malformed or oversized frame"),
    spec(4020, Closed, None, Some(-32001), "peer identity header from untrusted origin"),
    // --- posture ---
    spec(5001, Degrade, None, None, "re-attestation failed"),
    spec(5002, Degrade, None, None, "material drift detected"),
    spec(5010, Degrade, None, None, "credential expiring or expired"),
    spec(5030, Report, Some(200), None, "blast-radius depth limit reached, truncated"),
    // --- containment ---
    spec(6001, Closed, Some(403), None, "quarantine dual control missing"),
    spec(6002, Closed, Some(500), None, "revocation feed unwritable"),
    spec(6003, Report, Some(202), None, "mediator acknowledgement not received"),
    spec(6004, Closed, Some(403), None, "break-glass request outside policy"),
    // --- evidence ---
    spec(7001, Closed, Some(503), None, "blocking evidence sink unavailable"),
    spec(7002, Closed, Some(500), None, "audit chain append failed"),
    spec(7003, Report, Some(200), None, "audit chain break detected"),
    spec(7010, Report, Some(500), None, "export failed"),
    spec(7020, Closed, Some(503), None, "external pdp unreachable"),
    // --- platform ---
    spec(8001, Report, Some(422), None, "invalid policy, last-known-good retained"),
    spec(8002, Closed, Some(404), None, "unknown tenant or cross-tenant reference"),
    spec(8003, Closed, Some(503), None, "store write lock held by another writer"),
    spec(8004, Closed, None, None, "configuration invalid at startup"),
];

/// A `const fn` so the table above reads as rows rather than as struct
/// literals. `const fn` runs at compile time, which is why [`CODES`] can be a
/// `static` with no initialisation cost at runtime.
const fn spec(
    code: u16,
    fail: FailDirection,
    http: Option<u16>,
    rpc: Option<i32>,
    summary: &'static str,
) -> CodeSpec {
    CodeSpec {
        code,
        fail,
        http,
        rpc,
        summary,
    }
}

// ---------------------------------------------------------------------------
// WcError
// ---------------------------------------------------------------------------

/// The crate's error type: a code, an optional human detail, and an optional
/// underlying cause.
///
/// Deliberately **not** an enum of failure kinds: the kind *is* the code, and
/// the code is API. Deliberately not `Box<dyn Error>` either — a caller that
/// cannot ask "which code?" cannot decide anything.
#[derive(Debug)]
pub struct WcError {
    code: Code,
    detail: String,
    source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
}

/// The crate-wide result alias. `error::Result<T>` reads better than
/// `Result<T, WcError>` at ten thousand call sites.
pub type Result<T> = std::result::Result<T, WcError>;

impl WcError {
    /// A bare error with no detail.
    #[must_use]
    pub fn new(code: Code) -> Self {
        WcError {
            code,
            detail: String::new(),
            source: None,
        }
    }

    /// An error with a human-readable detail.
    #[must_use]
    pub fn with_detail(code: Code, detail: impl Into<String>) -> Self {
        WcError {
            code,
            detail: detail.into(),
            source: None,
        }
    }

    /// Attach the underlying cause — an io error, a JSON error, someone else's
    /// error type.
    #[must_use]
    pub fn with_source<E>(mut self, source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        self.source = Some(Box::new(source));
        self
    }

    /// The code. Callers switch on this — it is the whole reason this type
    /// exists.
    #[must_use]
    pub fn code(&self) -> Code {
        self.code
    }

    /// The human detail, empty if none was given.
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }

    /// Whether this error denies the operation in the given mode.
    #[must_use]
    pub fn denies_in(&self, mode: Mode) -> bool {
        self.code.denies_in(mode)
    }
}

impl fmt::Display for WcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.code, self.code.summary())?;
        if !self.detail.is_empty() {
            write!(f, ": {}", self.detail)?;
        }
        Ok(())
    }
}

impl std::error::Error for WcError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_deref()
            .map(|e| e as &(dyn std::error::Error + 'static))
    }
}

// ---------------------------------------------------------------------------
// Tests — these are the spec.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    // Inner attribute: applies to everything *inside* this module. Panicking on
    // a bad value is exactly what a test should do, so the workspace's
    // no-unwrap rule is lifted here and nowhere else.
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    // --- the table itself ---

    #[test]
    fn table_is_sorted_and_unique() {
        let mut prev = 0u16;
        for s in CODES {
            assert!(
                s.code > prev,
                "CODES must be sorted ascending and unique: {} follows {}",
                s.code,
                prev
            );
            prev = s.code;
        }
        assert_eq!(CODES.len(), 70, "the LLD §8.11 table has 70 codes");
    }

    #[test]
    fn every_row_is_findable() {
        for s in CODES {
            let code = Code::new(s.code).expect("row must be a valid code");
            let found = code.spec().expect("spec must find every row");
            assert_eq!(found.code, s.code);
            assert!(!found.summary.is_empty(), "WC-{} has no summary", s.code);
        }
    }

    #[test]
    fn table_categories_are_total() {
        // Proves the `unreachable!()` arm in Category::of is genuinely
        // unreachable for every code we define.
        for s in CODES {
            let _ = Code::new(s.code).expect("valid").category();
        }
    }

    #[test]
    fn unknown_numbers_are_rejected() {
        assert!(Code::new(9999).is_none());
        assert!(Code::new(0).is_none());
        assert!(Code::new(3109).is_some());
    }

    // --- Category ---

    #[test]
    fn categories_split_the_3xxx_block() {
        assert_eq!(
            Code::CONTRACT_NOT_FOUND.category(),
            Category::ContractLifecycle
        );
        assert_eq!(
            Code::STANDING_CAP_REACHED.category(),
            Category::ContractLifecycle
        );
        assert_eq!(Code::ALG_NOT_ASYMMETRIC.category(), Category::Verification);
        assert_eq!(Code::CONTRACT_OVERSIZE.category(), Category::Verification);
        assert_eq!(Code::IDENTITY_UNVERIFIABLE.category(), Category::Admission);
        assert_eq!(Code::DISCOVERY_THROTTLED.category(), Category::Registry);
        assert_eq!(Code::TOOL_UNCONTRACTED.category(), Category::Mediation);
        assert_eq!(Code::DRIFT_MATERIAL.category(), Category::Posture);
        assert_eq!(Code::MEDIATOR_ACK_MISSING.category(), Category::Containment);
        assert_eq!(Code::CHAIN_BROKEN.category(), Category::Evidence);
        assert_eq!(Code::STORE_LOCKED.category(), Category::Platform);
    }

    // --- Display / FromStr ---

    #[test]
    fn code_displays_zero_padded() {
        assert_eq!(Code::PIN_MISMATCH.to_string(), "WC-3108");
        assert_eq!(Code::IDENTITY_UNVERIFIABLE.to_string(), "WC-1001");
        assert_eq!(format!("{}", Code::CONFIG_INVALID), "WC-8004");
    }

    #[test]
    fn code_parses_both_forms() {
        assert_eq!("WC-3108".parse::<Code>(), Ok(Code::PIN_MISMATCH));
        assert_eq!("3108".parse::<Code>(), Ok(Code::PIN_MISMATCH));
    }

    #[test]
    fn code_parse_rejects_junk() {
        for bad in [
            "",
            "WC-",
            "WC-99999",
            "WC-9999",
            "pin mismatch",
            "WC-31O8",
            "-3108",
        ] {
            assert!(bad.parse::<Code>().is_err(), "{bad:?} must not parse");
        }
    }

    #[test]
    fn display_and_fromstr_round_trip() {
        for s in CODES {
            let code = Code::new(s.code).expect("valid");
            let round = code.to_string().parse::<Code>().expect("round trip");
            assert_eq!(code, round);
        }
    }

    // --- fail direction ---

    #[test]
    fn fail_directions_match_the_lld() {
        assert_eq!(
            Code::ENTITY_QUARANTINED.fail_direction(),
            FailDirection::Closed
        );
        assert_eq!(
            Code::PROVENANCE_UNVERIFIABLE.fail_direction(),
            FailDirection::ClosedUnlessObserve
        );
        assert_eq!(
            Code::DRIFT_MATERIAL.fail_direction(),
            FailDirection::Degrade
        );
        assert_eq!(
            Code::MEDIATOR_ACK_MISSING.fail_direction(),
            FailDirection::Report
        );
    }

    #[test]
    fn observe_mode_softens_only_what_it_may() {
        // Quarantine is never overridable — §7.8 fail-closed matrix.
        assert!(Code::ENTITY_QUARANTINED.denies_in(Mode::Enforce));
        assert!(Code::ENTITY_QUARANTINED.denies_in(Mode::Observe));

        // Unverifiable provenance is a finding in observe mode.
        assert!(Code::PROVENANCE_UNVERIFIABLE.denies_in(Mode::Enforce));
        assert!(!Code::PROVENANCE_UNVERIFIABLE.denies_in(Mode::Observe));

        // Degrade and Report never deny.
        assert!(!Code::DRIFT_MATERIAL.denies_in(Mode::Enforce));
        assert!(!Code::TTL_EXCEEDS_ZONE_BAR.denies_in(Mode::Enforce));
    }

    // --- WcError ---

    #[test]
    fn error_display_with_and_without_detail() {
        let bare = WcError::new(Code::PIN_MISMATCH);
        assert_eq!(bare.to_string(), "WC-3108 surface pin mismatch");

        let detailed = WcError::with_detail(
            Code::PIN_MISMATCH,
            "presented sha256:ab12 != pinned sha256:cd34",
        );
        assert_eq!(
            detailed.to_string(),
            "WC-3108 surface pin mismatch: presented sha256:ab12 != pinned sha256:cd34"
        );
    }

    #[test]
    fn error_accepts_both_str_and_string() {
        let from_str = WcError::with_detail(Code::POLICY_DENIED, "zone pair forbidden");
        let owned = format!("tier {} too high", 1);
        let from_string = WcError::with_detail(Code::POLICY_DENIED, owned);
        assert_eq!(from_str.code(), Code::POLICY_DENIED);
        assert_eq!(from_string.detail(), "tier 1 too high");
    }

    #[test]
    fn error_carries_its_source() {
        use std::error::Error as _;

        let io = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "locked");
        let err = WcError::with_detail(Code::STORE_LOCKED, "wc.lock held").with_source(io);

        assert_eq!(err.code(), Code::STORE_LOCKED);
        let source = err.source().expect("source must be exposed");
        assert!(source.to_string().contains("locked"));
    }

    #[test]
    fn error_without_source_reports_none() {
        use std::error::Error as _;
        assert!(WcError::new(Code::NO_CONTRACT).source().is_none());
    }

    #[test]
    fn result_alias_flows_through_question_mark() {
        // The point of the alias: `?` composes without naming the error type.
        fn inner() -> Result<u16> {
            Err(WcError::new(Code::NO_CONTRACT))
        }
        fn outer() -> Result<u16> {
            let v = inner()?;
            Ok(v + 1)
        }
        assert_eq!(outer().unwrap_err().code(), Code::NO_CONTRACT);
    }
}
