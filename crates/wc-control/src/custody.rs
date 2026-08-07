//! Which key signs what, and the rules that keep them apart
//! (`docs/key-custody.md`, production-readiness P0 #5c–5e).
//!
//! Six operations in this system sign. They do **not** want the same custody, and until
//! now the only thing enforcing any of that was an operator's intent:
//!
//! * **`--require-external-signing` reached one of the six.** It was checked inside the
//!   CLI's `issuer_key()` and inside the anchor path, and nowhere else — so an estate
//!   that set the posture, and believed no signing key was read from local disk, could
//!   still run `connect quarantine --revocation-key ./revoke.pem` and
//!   `connect bundle export --signing-key ./envelope.pem` with nothing objecting. A
//!   posture that covers a third of what it claims is worse than no posture, because it
//!   is believed.
//! * **Nothing kept the approver keys away from the service's keys.** `--approver-key`
//!   and `--issuer-key` could name the same file. A control plane that can sign its own
//!   approvals makes dual control theatre, and the theatre is indistinguishable from the
//!   real thing in the evidence chain afterwards — both produce a valid approval proof.
//! * **Nothing distinguished the two revocation keys.** `revoke-offline` exists so
//!   containment works when the KMS does not, and its use is meant to be a
//!   wake-somebody event because it happens approximately never. Nothing knew which
//!   `kid` that was, so nothing could escalate.
//!
//! This module is the one place those rules live, so a new signing site inherits them
//! rather than re-deciding them.
//!
//! # Fingerprints, not paths
//!
//! Separation is checked on **key material**, not on the filename. Comparing paths would
//! be defeated by `cp issuer.pem approver.pem`, which is exactly what an operator in a
//! hurry does. A delegated signer is fingerprinted on its command, for the same reason:
//! two roles pointing at one KMS key is the thing being prevented, and the command is
//! all this process can see of it.
//!
//! The fingerprint is a salted digest and is never the key itself, so it is safe to put
//! in an error message — which matters, because an error that cannot say *which* two
//! roles collided is an error an operator cannot act on.

use std::collections::BTreeMap;

use wc_core::contract::{Algorithm, IssuerKey};
use wc_core::error::{Code, Result, WcError};

use crate::signer::CommandSigner;

/// Domain separation, so a fingerprint here can never be confused with a content
/// digest or a surface digest elsewhere in the system.
const FINGERPRINT_DOMAIN: &[u8] = b"warden-connect/custody-fingerprint/v1\0";

// ---------------------------------------------------------------------------
// Roles
// ---------------------------------------------------------------------------

/// A signing operation, and therefore a custody decision.
///
/// Named rather than passed as strings so that adding a seventh signing site is a
/// compile error in the `match`es below rather than a role with no rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Role {
    /// Contract minting. KMS, no local copy.
    Issuer,
    /// Evidence-chain checkpoints. HSM or offline — move this one first, because a
    /// checkpoint signed by a key the host holds proves only that the host agrees with
    /// itself.
    Anchor,
    /// Routine revocation. KMS; fast, scriptable, no ceremony.
    RevokeOnline,
    /// Break-glass revocation. Non-exportable on a hardware token, PIN split M-of-N.
    /// Must work when the KMS does not.
    RevokeOffline,
    /// A human approver. **Never** the service's KMS.
    Approver,
    /// The air-gapped bundle envelope. Follows the issuer key; low volume.
    Envelope,
    /// A synthetic key for `connect bench`. Signs nothing that leaves the process.
    Benchmark,
}

impl Role {
    /// The word that appears in evidence and in operator output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Role::Issuer => "issuer",
            Role::Anchor => "anchor",
            Role::RevokeOnline => "revoke-online",
            Role::RevokeOffline => "revoke-offline",
            Role::Approver => "approver",
            Role::Envelope => "envelope",
            Role::Benchmark => "benchmark",
        }
    }

    /// The flag pair an operator uses for this role, for error messages that can be
    /// acted on without reading source.
    #[must_use]
    pub const fn flags(self) -> (&'static str, &'static str) {
        match self {
            Role::Issuer => ("--issuer-key", "--signer"),
            Role::Anchor => ("--anchor-key", "--anchor-signer"),
            Role::RevokeOnline | Role::RevokeOffline => ("--revocation-key", "--revocation-signer"),
            Role::Approver => ("--approver-key", "--approver-signer"),
            Role::Envelope => ("--signing-key", "--envelope-signer"),
            Role::Benchmark => ("--signing-key", "--signer"),
        }
    }

    /// Whether `--require-external-signing` applies to this role.
    ///
    /// Only the benchmark is exempt, and it is exempt because it signs nothing that
    /// leaves the process — `connect bench` measures the cost of signing and throws the
    /// signature away. The exemption is stated here rather than achieved by the role
    /// simply not being routed through this module, which is how the other five came to
    /// be unenforced.
    #[must_use]
    pub const fn honours_external_signing(self) -> bool {
        !matches!(self, Role::Benchmark)
    }

    /// Whether this role is a human's key and must therefore never share custody with
    /// a service role.
    #[must_use]
    pub const fn is_human(self) -> bool {
        matches!(self, Role::Approver)
    }
}

// ---------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------

/// What an operator asked for, before it is a key.
#[derive(Debug, Clone, Copy, Default)]
pub struct Request<'a> {
    /// A PEM on this disk.
    pub pem_path: Option<&'a str>,
    /// A command that signs elsewhere.
    pub signer_command: Option<&'a str>,
}

/// Load a signing key for a role, applying the custody rules.
///
/// Three refusals, all of them for the same reason — a key whose custody is a guess is
/// worse than a missing key:
///
/// 1. **Both forms given.** Never resolved by precedence. An operator who believes their
///    key is in a token and finds a PEM was used has the worst outcome available here.
/// 2. **Neither given.** Named with both flags for the role.
/// 3. **A PEM while `require_external` is set**, for every role that honours it.
pub fn resolve(
    role: Role,
    request: Request<'_>,
    kid: &str,
    alg: Algorithm,
    require_external: bool,
) -> Result<IssuerKey> {
    let (pem_flag, signer_flag) = role.flags();
    match (request.pem_path, request.signer_command) {
        (Some(_), Some(_)) => Err(WcError::with_detail(
            Code::CONFIG_INVALID,
            format!(
                "{pem_flag} and {signer_flag} both given for the {} key; one names a key on \
                 this disk and the other a key held elsewhere, so which is in force must not \
                 be a guess",
                role.as_str()
            ),
        )),
        (None, None) => Err(WcError::with_detail(
            Code::CONFIG_INVALID,
            format!(
                "the {} key is required: pass {pem_flag} PEM or {signer_flag} COMMAND",
                role.as_str()
            ),
        )),
        (None, Some(command)) => CommandSigner::parse(command)?.into_issuer_key(kid, alg),
        (Some(path), None) => {
            if require_external && role.honours_external_signing() {
                return Err(WcError::with_detail(
                    Code::CONFIG_INVALID,
                    format!(
                        "--require-external-signing is set and {pem_flag} {path} is the {} key \
                         on this disk; use {signer_flag} COMMAND",
                        role.as_str()
                    ),
                ));
            }
            let pem = std::fs::read(path).map_err(|e| {
                WcError::with_detail(
                    Code::CONFIG_INVALID,
                    format!("cannot read the {} key {path}", role.as_str()),
                )
                .with_source(e)
            })?;
            match alg {
                Algorithm::EdDSA => IssuerKey::ed_pem(kid, &pem),
                other => IssuerKey::ec_pem(kid, &pem, other),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Separation (5d)
// ---------------------------------------------------------------------------

/// An opaque, non-reversible identifier for key material.
///
/// Derived from the *private* PEM's base64 body, or from a delegated signer's command.
/// The armour lines and all whitespace are dropped first, so the same key saved with
/// different line endings — or with a different `-----BEGIN-----` label — fingerprints
/// the same. Otherwise the separation check would be defeated by `openssl` reformatting
/// a file, which is not an attack, just a Tuesday.
///
/// **What it cannot equate:** the same key in two different *encodings* — PKCS#8 versus
/// SEC1, or DER versus PEM. Those have different bytes, and telling they are one key
/// needs an ASN.1 parse this module deliberately does not do (see `keys::jwk_from_pem`
/// for the same stance). So the check catches a copied key and misses a re-encoded one;
/// it raises the cost of the mistake without claiming to make it impossible.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Fingerprint(String);

impl Fingerprint {
    /// The short form that appears in an error message. Never the key.
    #[must_use]
    pub fn short(&self) -> &str {
        &self.0[..12.min(self.0.len())]
    }

    /// Fingerprint a PEM's contents.
    #[must_use]
    pub fn of_pem(pem: &[u8]) -> Fingerprint {
        // Only the base64 payload: armour lines are dropped whole, not just stripped of
        // their dashes, so `-----BEGIN EC PRIVATE KEY-----` and
        // `-----BEGIN PRIVATE KEY-----` over the same body are one fingerprint.
        let text = String::from_utf8_lossy(pem);
        let body: String = text
            .lines()
            .map(str::trim)
            .filter(|line| !line.starts_with("-----") && !line.contains(':'))
            .collect();
        // A file with no armour at all (a raw base64 blob, or DER) still fingerprints —
        // on whatever it does contain, with whitespace removed. Returning a constant for
        // the unparseable case would make every malformed key collide with every other.
        let body = if body.is_empty() {
            text.split_whitespace().collect::<String>()
        } else {
            body
        };
        Fingerprint::digest(b"pem", body.as_bytes())
    }

    /// Fingerprint a delegated signer command.
    #[must_use]
    pub fn of_command(command: &str) -> Fingerprint {
        // Collapsed whitespace: `kms-sign  --key alpha` and `kms-sign --key alpha` are
        // one KMS key, and treating them as two would let the check be bypassed by
        // typing an extra space.
        let collapsed = command.split_whitespace().collect::<Vec<_>>().join(" ");
        Fingerprint::digest(b"command", collapsed.as_bytes())
    }

    fn digest(kind: &[u8], material: &[u8]) -> Fingerprint {
        // Built through `wc_core::util` rather than by taking a `sha2` dependency here:
        // the crate would resolve to the same code and the dependency ceiling exists so
        // that additions are argued rather than incidental.
        let mut input =
            Vec::with_capacity(FINGERPRINT_DOMAIN.len() + kind.len() + material.len() + 1);
        input.extend_from_slice(FINGERPRINT_DOMAIN);
        input.extend_from_slice(kind);
        input.push(0);
        input.extend_from_slice(material);
        let digest = wc_core::util::sha256_bytes(&input);
        Fingerprint(digest.iter().map(|b| format!("{b:02x}")).collect())
    }

    /// Fingerprint whatever an operator supplied for a role, without loading the key.
    ///
    /// Returns `None` when neither form was given — the caller's own resolution will
    /// produce the better error.
    pub fn of_request(request: Request<'_>) -> Result<Option<Fingerprint>> {
        if let Some(command) = request.signer_command {
            return Ok(Some(Fingerprint::of_command(command)));
        }
        match request.pem_path {
            None => Ok(None),
            Some(path) => {
                let pem = std::fs::read(path).map_err(|e| {
                    WcError::with_detail(Code::CONFIG_INVALID, format!("cannot read {path}"))
                        .with_source(e)
                })?;
                Ok(Some(Fingerprint::of_pem(&pem)))
            }
        }
    }
}

/// Which key material is in use for which roles, so a collision can be refused.
///
/// The rule is not "every role needs its own key" — `Envelope` follows `Issuer` by
/// design, and that is fine. The rule is that **a human's key and a service's key must
/// never be the same material**, and that **two approvers must not be one key**.
#[derive(Debug, Default)]
pub struct Separation {
    seen: BTreeMap<Fingerprint, Vec<(Role, String)>>,
}

impl Separation {
    /// An empty ledger.
    #[must_use]
    pub fn new() -> Separation {
        Separation::default()
    }

    /// Record a role's key material, refusing a collision that breaks separation.
    ///
    /// `label` distinguishes two holders of the same role — the two approvers in dual
    /// control — so the error can say *which* human, not just "approver".
    pub fn observe(
        &mut self,
        role: Role,
        label: &str,
        fingerprint: Option<Fingerprint>,
    ) -> Result<()> {
        let Some(fingerprint) = fingerprint else {
            return Ok(());
        };
        if let Some(existing) = self.seen.get(&fingerprint) {
            for (other_role, other_label) in existing {
                if let Some(reason) = collision(role, *other_role, label, other_label) {
                    return Err(WcError::with_detail(
                        Code::CONFIG_INVALID,
                        format!(
                            "the {} key ({label}) and the {} key ({other_label}) are the same \
                             key material [{}]: {reason}",
                            role.as_str(),
                            other_role.as_str(),
                            fingerprint.short()
                        ),
                    ));
                }
            }
        }
        self.seen
            .entry(fingerprint)
            .or_default()
            .push((role, label.to_string()));
        Ok(())
    }

    /// Record a role and its resolved key in one step, for a call site that has both.
    pub fn observe_request(&mut self, role: Role, label: &str, request: Request<'_>) -> Result<()> {
        self.observe(role, label, Fingerprint::of_request(request)?)
    }

    /// How many distinct key materials have been seen.
    #[must_use]
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// Whether nothing has been recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

/// Why two roles sharing key material is a problem, or `None` if it is not.
///
/// The asymmetry is deliberate. `Issuer` and `Envelope` sharing is documented custody
/// (5e: "follow the issuer key"), so refusing it would refuse a supported deployment.
/// A human sharing with a service is never supported, in either direction.
fn collision(a: Role, b: Role, a_label: &str, b_label: &str) -> Option<&'static str> {
    if a.is_human() && b.is_human() {
        return if a_label == b_label {
            // The same approver named twice is a different mistake, caught elsewhere by
            // comparing the human ids. Not a separation failure.
            None
        } else {
            Some(
                "dual control signed by one key is not dual control — two approvers must \
                 hold two keys, or one compromise satisfies both",
            )
        };
    }
    if a.is_human() != b.is_human() {
        return Some(
            "an approver key must never be a key the service holds — if the control plane \
             can sign its own approvals, dual control is theatre and the evidence chain \
             cannot tell the difference afterwards",
        );
    }
    // Two service roles. The one pairing that is a real problem:
    if matches!(
        (a, b),
        (Role::RevokeOnline, Role::RevokeOffline) | (Role::RevokeOffline, Role::RevokeOnline)
    ) {
        return Some(
            "the break-glass revocation key must not be a copy of the online one — the \
             point of two is that compromise of either does not imply the other, and that \
             containment still works when the KMS does not",
        );
    }
    None
}

// ---------------------------------------------------------------------------
// Revocation custody (5c)
// ---------------------------------------------------------------------------

/// The two revocation `kid`s, and which one is break-glass.
///
/// Verification needed no change for this: `SignedRevocation` already carries a per-entry
/// `kid` and resolves it against an `IssuerKeys` map, so a mediator can trust both keys
/// at once and the feed records which one signed each order. What was missing is on this
/// side — **nothing knew which `kid` was the offline one**, so nothing could treat its
/// use as the exceptional event it is.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RevocationCustody {
    /// The routine key: KMS, scriptable.
    pub online_kid: Option<String>,
    /// The break-glass key: hardware token, PIN split M-of-N, used when the KMS is not
    /// available.
    pub offline_kid: Option<String>,
}

impl RevocationCustody {
    /// Declare the pair.
    ///
    /// Refuses one `kid` used for both. Two names for one key is the failure this whole
    /// sub-item exists to prevent: it reads in a runbook as two keys, and buys none of
    /// the three properties two keys are for.
    pub fn new(online_kid: Option<&str>, offline_kid: Option<&str>) -> Result<RevocationCustody> {
        if let (Some(on), Some(off)) = (online_kid, offline_kid) {
            if on == off {
                return Err(WcError::with_detail(
                    Code::CONFIG_INVALID,
                    format!(
                        "--revocation-kid and --break-glass-kid are both {on:?}; one kid for \
                         both roles reads as two keys and is one, so neither the isolation \
                         nor the alerting they exist for holds"
                    ),
                ));
            }
        }
        Ok(RevocationCustody {
            online_kid: online_kid.map(str::to_string),
            offline_kid: offline_kid.map(str::to_string),
        })
    }

    /// Which role a `kid` is signing in.
    ///
    /// An undeclared `kid` is `RevokeOnline`, because that is the routine path and an
    /// estate that has not adopted two keys yet must keep working. It is **never**
    /// silently treated as offline: guessing that direction would page somebody for
    /// ordinary work, and an alert that fires on routine operations is an alert that
    /// gets muted, which is how the real one gets missed.
    #[must_use]
    pub fn role_of(&self, kid: &str) -> Role {
        match self.offline_kid.as_deref() {
            Some(offline) if offline == kid => Role::RevokeOffline,
            _ => Role::RevokeOnline,
        }
    }

    /// Whether this `kid` is the break-glass key.
    #[must_use]
    pub fn is_break_glass(&self, kid: &str) -> bool {
        self.role_of(kid) == Role::RevokeOffline
    }

    /// Whether a break-glass revocation with this `kid` may proceed.
    ///
    /// Requires the operator to have said so explicitly. The offline key is reached at
    /// 03:00 during an incident, from a runbook, and the failure to prevent is reaching
    /// for it out of habit — because a break-glass path used routinely stops being
    /// exceptional, and then its alert stops meaning anything.
    pub fn authorise(&self, kid: &str, acknowledged: bool) -> Result<Role> {
        let role = self.role_of(kid);
        if role == Role::RevokeOffline && !acknowledged {
            return Err(WcError::with_detail(
                Code::CONFIG_INVALID,
                format!(
                    "{kid:?} is the break-glass revocation key; it is for when the KMS or the \
                     control plane is unavailable, and its use pages somebody. Pass \
                     --break-glass to confirm that is what you mean, or sign with the online \
                     key"
                ),
            ));
        }
        Ok(role)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    const ES256_PRIV: &[u8] = include_bytes!("../../../fixtures/keys/test_issuer_es256_priv.pem");

    struct Temp(std::path::PathBuf);

    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn write(name: &str, bytes: &[u8]) -> Temp {
        let path = std::env::temp_dir().join(format!("wc-custody-{}-{name}", std::process::id()));
        std::fs::write(&path, bytes).unwrap();
        Temp(path)
    }

    fn pem(path: &std::path::Path) -> Request<'_> {
        Request {
            pem_path: path.to_str(),
            signer_command: None,
        }
    }

    // --- the posture, applied uniformly ------------------------------------

    #[test]
    fn require_external_signing_now_reaches_every_role_that_signs() {
        // The defect this module exists for. `--require-external-signing` was checked in
        // the CLI's issuer path and the anchor path and nowhere else, so an estate that
        // set the posture could still revoke and export bundles with keys on local disk
        // — and would have had no way to find out except by reading the source.
        let f = write("posture.pem", ES256_PRIV);
        for role in [
            Role::Issuer,
            Role::Anchor,
            Role::RevokeOnline,
            Role::RevokeOffline,
            Role::Approver,
            Role::Envelope,
        ] {
            let err = resolve(role, pem(&f.0), "k1", Algorithm::ES256, true).unwrap_err();
            assert_eq!(err.code(), Code::CONFIG_INVALID, "{role:?}");
            let text = format!("{err}");
            assert!(
                text.contains(role.as_str()),
                "the error must name the role: {text}"
            );
            assert!(
                text.contains(role.flags().1),
                "and the flag that fixes it: {text}"
            );
        }
    }

    #[test]
    fn the_benchmark_key_is_exempt_and_says_why() {
        // `connect bench` measures the cost of signing and discards the signature, so a
        // synthetic PEM is correct there. The exemption is a stated property of the role
        // rather than the role simply not being routed through here — which is precisely
        // how the other five ended up unenforced.
        let f = write("bench.pem", ES256_PRIV);
        assert!(resolve(Role::Benchmark, pem(&f.0), "k1", Algorithm::ES256, true).is_ok());
        assert!(!Role::Benchmark.honours_external_signing());
        for role in [
            Role::Issuer,
            Role::Anchor,
            Role::RevokeOffline,
            Role::Approver,
        ] {
            assert!(role.honours_external_signing(), "{role:?}");
        }
    }

    #[test]
    fn both_custody_forms_is_an_error_for_every_role() {
        let f = write("both.pem", ES256_PRIV);
        for role in [
            Role::Issuer,
            Role::RevokeOnline,
            Role::Approver,
            Role::Envelope,
        ] {
            let err = resolve(
                role,
                Request {
                    pem_path: f.0.to_str(),
                    signer_command: Some("kms-sign"),
                },
                "k1",
                Algorithm::ES256,
                false,
            )
            .unwrap_err();
            assert!(
                format!("{err}").contains("must not"),
                "resolving by precedence is the thing being refused: {err}"
            );
        }
    }

    #[test]
    fn a_missing_key_names_both_flags_for_its_role() {
        let err = resolve(
            Role::RevokeOnline,
            Request::default(),
            "k1",
            Algorithm::ES256,
            false,
        )
        .unwrap_err();
        let text = format!("{err}");
        assert!(text.contains("--revocation-key"), "{text}");
        assert!(text.contains("--revocation-signer"), "{text}");
    }

    #[test]
    fn a_delegated_key_is_accepted_under_the_posture() {
        let key = resolve(
            Role::RevokeOffline,
            Request {
                pem_path: None,
                signer_command: Some("/usr/bin/true"),
            },
            "revoke-offline",
            Algorithm::ES256,
            true,
        )
        .unwrap();
        assert_eq!(key.custody(), wc_core::contract::Custody::Delegated);
        assert_eq!(key.kid(), "revoke-offline");
    }

    // --- separation (5d) ---------------------------------------------------

    #[test]
    fn an_approver_key_that_is_the_service_key_is_refused() {
        // The control this sub-item is for. Today's arrangement was "separate PEMs, kept
        // apart by the operator" — and `cp issuer.pem approver.pem` satisfied it while
        // making dual control theatre. Afterwards the evidence chain cannot tell: both
        // arrangements produce a valid approval proof.
        let issuer = write("sep-issuer.pem", ES256_PRIV);
        let approver = write("sep-approver.pem", ES256_PRIV); // same material, different file

        let mut sep = Separation::new();
        sep.observe_request(Role::Issuer, "control-plane", pem(&issuer.0))
            .unwrap();
        let err = sep
            .observe_request(Role::Approver, "human:vijay", pem(&approver.0))
            .unwrap_err();

        let text = format!("{err}");
        assert!(text.contains("dual control is theatre"), "{text}");
        assert!(text.contains("human:vijay"), "it must name who: {text}");
        assert!(text.contains("issuer"), "and which service role: {text}");
    }

    #[test]
    fn the_check_survives_re_encoding_because_it_is_on_material_not_on_paths() {
        // A path comparison would be defeated by a copy, and a byte comparison by a
        // reformat. Both are what an operator actually does.
        let a = Fingerprint::of_pem(ES256_PRIV);
        let noisy: Vec<u8> = String::from_utf8_lossy(ES256_PRIV)
            .replace('\n', "\r\n")
            .into_bytes();
        assert_eq!(
            a,
            Fingerprint::of_pem(&noisy),
            "line endings must not matter"
        );

        // The armour label does not matter, because only the base64 payload is digested.
        let relabelled = String::from_utf8_lossy(ES256_PRIV)
            .replace("PRIVATE KEY", "EC PRIVATE KEY")
            .into_bytes();
        assert_eq!(
            a,
            Fingerprint::of_pem(&relabelled),
            "the label is not the key"
        );

        // What it does *not* do, stated so nobody later reads the check as stronger than
        // it is: a genuine re-encode changes the base64, so PKCS#8 and SEC1 forms of one
        // key are two fingerprints. Equating them needs an ASN.1 parse this module does
        // not do. The check raises the cost of copying a key; it does not make sharing
        // one impossible.
        let reencoded = String::from_utf8_lossy(ES256_PRIV).replace("MIGH", "MIGI");
        assert_ne!(a, Fingerprint::of_pem(reencoded.as_bytes()));

        // And a genuinely different key is a different fingerprint.
        let other = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../fixtures/keys/test_anchor_priv.pem"),
        )
        .unwrap();
        assert_ne!(a, Fingerprint::of_pem(&other));
    }

    #[test]
    fn two_approvers_sharing_one_key_is_refused() {
        // Two human ids and one key satisfies every id check in the system and defeats
        // the control they exist for.
        let k = write("dual.pem", ES256_PRIV);
        let mut sep = Separation::new();
        sep.observe_request(Role::Approver, "human:a", pem(&k.0))
            .unwrap();
        let err = sep
            .observe_request(Role::Approver, "human:b", pem(&k.0))
            .unwrap_err();
        assert!(
            format!("{err}").contains("two approvers must hold two keys"),
            "{err}"
        );
    }

    #[test]
    fn the_same_approver_twice_is_not_a_separation_failure() {
        // Naming one human twice is a different mistake with its own error; reporting it
        // as broken separation would send the operator to fix the wrong thing.
        let k = write("same.pem", ES256_PRIV);
        let mut sep = Separation::new();
        sep.observe_request(Role::Approver, "human:a", pem(&k.0))
            .unwrap();
        assert!(sep
            .observe_request(Role::Approver, "human:a", pem(&k.0))
            .is_ok());
    }

    #[test]
    fn the_envelope_key_may_follow_the_issuer_key() {
        // Documented custody (5e), so refusing it would refuse a supported deployment.
        // The separation rule is about humans versus services, not "every role needs its
        // own key" — a blanket rule would be easier to implement and wrong.
        let k = write("follow.pem", ES256_PRIV);
        let mut sep = Separation::new();
        sep.observe_request(Role::Issuer, "cp", pem(&k.0)).unwrap();
        assert!(sep.observe_request(Role::Envelope, "cp", pem(&k.0)).is_ok());
    }

    #[test]
    fn the_break_glass_revocation_key_may_not_be_a_copy_of_the_online_one() {
        let k = write("revoke.pem", ES256_PRIV);
        let mut sep = Separation::new();
        sep.observe_request(Role::RevokeOnline, "revoke-online", pem(&k.0))
            .unwrap();
        let err = sep
            .observe_request(Role::RevokeOffline, "revoke-offline", pem(&k.0))
            .unwrap_err();
        assert!(format!("{err}").contains("when the KMS does not"), "{err}");
    }

    #[test]
    fn two_roles_pointing_at_one_kms_key_is_caught_too() {
        // A delegated signer hides the key, so material cannot be compared — but the
        // command is what this process can see of it, and two roles invoking the same
        // KMS key is exactly the arrangement being prevented. Whitespace is collapsed so
        // an extra space cannot bypass the check.
        let mut sep = Separation::new();
        let issuer = Request {
            pem_path: None,
            signer_command: Some("kms-sign --key alpha"),
        };
        let approver = Request {
            pem_path: None,
            signer_command: Some("kms-sign  --key   alpha"),
        };
        sep.observe_request(Role::Issuer, "cp", issuer).unwrap();
        assert!(sep
            .observe_request(Role::Approver, "human:a", approver)
            .is_err());
    }

    #[test]
    fn a_fingerprint_never_carries_the_key() {
        let f = Fingerprint::of_pem(ES256_PRIV);
        let body = String::from_utf8_lossy(ES256_PRIV);
        assert_eq!(f.short().len(), 12);
        for line in body
            .lines()
            .filter(|l| !l.starts_with("---") && l.len() > 8)
        {
            assert!(
                !f.0.contains(line.trim()),
                "the fingerprint appears in error messages and must not be reversible"
            );
        }
    }

    // --- revocation custody (5c) ------------------------------------------

    #[test]
    fn one_kid_for_both_revocation_roles_is_refused() {
        let err = RevocationCustody::new(Some("revoke-1"), Some("revoke-1")).unwrap_err();
        assert!(
            format!("{err}").contains("reads as two keys and is one"),
            "{err}"
        );
    }

    #[test]
    fn the_offline_kid_needs_an_explicit_acknowledgement() {
        // A break-glass path reached out of habit stops being exceptional, and then the
        // alert on it stops meaning anything.
        let c = RevocationCustody::new(Some("revoke-online"), Some("revoke-offline")).unwrap();

        let err = c.authorise("revoke-offline", false).unwrap_err();
        let text = format!("{err}");
        assert!(text.contains("--break-glass"), "{text}");
        assert!(text.contains("pages somebody"), "{text}");

        assert_eq!(
            c.authorise("revoke-offline", true).unwrap(),
            Role::RevokeOffline
        );
        // And the online key is never gated by it.
        assert_eq!(
            c.authorise("revoke-online", false).unwrap(),
            Role::RevokeOnline
        );
    }

    #[test]
    fn an_undeclared_kid_is_online_never_offline() {
        // An estate that has not adopted two keys must keep working, and must not be
        // paged for routine revocation. Guessing "offline" would produce an alert that
        // fires on ordinary work, which is an alert that gets muted.
        let none = RevocationCustody::default();
        assert_eq!(none.role_of("whatever"), Role::RevokeOnline);
        assert!(!none.is_break_glass("whatever"));
        assert!(none.authorise("whatever", false).is_ok());

        let one_sided = RevocationCustody::new(None, Some("revoke-offline")).unwrap();
        assert!(!one_sided.is_break_glass("something-else"));
        assert!(one_sided.is_break_glass("revoke-offline"));
    }
}
