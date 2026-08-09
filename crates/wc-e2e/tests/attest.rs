//! Admission through the **real** verifiers, to `Attested` (§8.7.1 stages 1–5).
//!
//! `admission` already had a test that reached `Posture::Attested`, and it reached it
//! through stand-ins declared in its own test module — `RealIdentity` returning
//! `verified: true` without looking at anything. That proves the *stage machinery*
//! composes, which is worth proving, and it proves nothing about whether a party can
//! become attested using the code that ships.
//!
//! This file closes that gap. `JwtSvidIdentity`, `JwksCardVerifier` and
//! `DsseProvenanceVerifier` are wired into one `AdmissionCtx`, pointed at material in
//! `fixtures/attest/`, and driven through `admission::admit`.
//!
//! Two properties make it a real test rather than a round trip:
//!
//! * **The material was not minted by this repository.**
//!   `scripts/gen-attest-fixtures.py` builds it with `cryptography`, assembling the
//!   ES256 signatures as raw `R‖S` and the DSSE pre-authentication encoding from the
//!   spec text. Agreement is therefore two independent readings of SPIFFE, JOSE and
//!   DSSE, not one implementation talking to itself.
//! * **Three distinct keys.** The SPIFFE bundle, the card signer and the builder are
//!   three parties, so they get three keypairs. A single key would let this pass while
//!   the code confused the roles — and the negative case below proves it does not.
//!
//! A spec reading catches a disagreement about what a specification *says*; only another
//! implementation catches a disagreement about what an issuer actually *emits*. Both
//! matter, so both are here — the interop sections at the bottom of this file add real
//! output from **SPIRE 1.15.2** (stage 1, `fixtures/spire/`) and **cosign v3.1.3**
//! (stage 4, `fixtures/cosign/`) beside the minted material, rather than replacing it.
//!
//! What is still not proven: **stages 2 and 3**. There is no reference implementation of
//! a signed A2A card to disagree with, so the card verifier is checked only against our
//! own reading. That is exactly the position stage 4 was in before cosign, and cosign
//! showed stage 4 was rejecting every real attestation.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde_json::Value;

use wc_control::admission::{
    self, AdmissionCtx, AdmissionRequest, Declared, IdentityVerifier, InlineSurface, NoScreening,
    TierRules,
};
use wc_control::attest::{DsseProvenanceVerifier, JwksCardVerifier, JwtSvidIdentity};
use wc_control::screen::{Acceptances, NameIndex, RulesetScreener, ScreenMode, ScreenRules};
use wc_core::canon::{Limits, SurfaceKind};
use wc_core::contract::{Algorithm, IssuerKeys};
use wc_core::error::{Code, Mode};
use wc_core::model::{EntityId, HumanRef, Kind, Posture, ZoneId};

/// The instant the fixtures were minted for. Their `exp` is an hour after this.
const NOW: u64 = 1_785_312_500;

fn dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/attest")
}

fn read(name: &str) -> Vec<u8> {
    let path = dir().join(name);
    std::fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "{}: {e}\n\nRun `python3 scripts/gen-attest-fixtures.py` from the repository \
             root. The fixtures are generated rather than committed-by-hand so that a \
             real SPIRE token can replace them.",
            path.display()
        )
    })
}

fn manifest() -> Value {
    serde_json::from_slice(&read("manifest.json")).unwrap()
}

fn one_key(pem: &str, kid: &str) -> IssuerKeys {
    let mut keys = IssuerKeys::new();
    keys.add_ec_pem(kid, &read(pem), Algorithm::ES256)
        .expect("fixture public key loads");
    keys
}

fn svid() -> String {
    String::from_utf8(read("jwt-svid.token"))
        .unwrap()
        .trim()
        .to_string()
}

fn card() -> Value {
    serde_json::from_slice(&read("agent-card.signed.json")).unwrap()
}

fn envelope() -> Value {
    serde_json::from_slice(&read("provenance.dsse.json")).unwrap()
}

fn digest() -> String {
    String::from_utf8(read("artifact.digest"))
        .unwrap()
        .trim()
        .to_string()
}

fn request(id: &str, card: Value) -> AdmissionRequest {
    AdmissionRequest {
        kind: Kind::Agent,
        id: Some(EntityId::new(id).unwrap()),
        card: Some(card),
        endpoint: None,
        attestation: Vec::new(),
        owner: HumanRef::new("human:priya@org").unwrap(),
        zone: ZoneId::new("internal.apac-ops").unwrap(),
        declared: Declared {
            data_classes: vec!["financial".to_string()],
            jurisdictions: vec!["SG".to_string()],
            requested_tier: None,
            service: Some("payments-recon".to_string()),
        },
        // Enforce, because that is the mode the verifiers are for. In observe a failed
        // stage becomes a finding, which would let this pass while proving less.
        mode: Mode::Enforce,
    }
}

/// Everything a full admission needs, held together so the tests can vary one thing.
struct Rig {
    bundle: IssuerKeys,
    card_keys: IssuerKeys,
    builder_keys: IssuerKeys,
    audience: String,
    builders: BTreeSet<String>,
}

impl Rig {
    fn new() -> Rig {
        let m = manifest();
        let mut builders = BTreeSet::new();
        builders.insert(m["builder"].as_str().unwrap().to_string());
        Rig {
            bundle: one_key("spiffe-bundle.pub.pem", "spiffe-bundle-1"),
            card_keys: one_key("card-signer.pub.pem", "card-signer-1"),
            builder_keys: one_key("builder.pub.pem", "builder-1"),
            audience: m["audience"].as_str().unwrap().to_string(),
            builders,
        }
    }
}

// ===========================================================================
// The happy path — the thing that had never been exercised
// ===========================================================================

#[test]
fn all_four_stages_pass_through_the_real_verifiers_and_the_party_is_attested() {
    let rig = Rig::new();
    let m = manifest();
    let card = card();

    let identity = JwtSvidIdentity {
        keys: &rig.bundle,
        audience: rig.audience.clone(),
        token: svid(),
        leeway: 60,
        now: NOW,
    };
    let card_verifier = JwksCardVerifier {
        keys: &rig.card_keys,
        require_signature: true,
    };
    let provenance = DsseProvenanceVerifier {
        keys: &rig.builder_keys,
        envelopes: vec![envelope()],
        artifact_digest: Some(digest()),
        allowed_builders: rig.builders.clone(),
    };
    let source = InlineSurface::new(SurfaceKind::A2aCard, card.clone());
    // Stage 5 for real, with a calibrated ruleset in enforce mode — otherwise the
    // "stages 1-5" in this file's title would be four stages and a skip.
    let rules = ScreenRules {
        calibrated: true,
        ..ScreenRules::default()
    };
    let acceptances = Acceptances::default();
    let names = NameIndex::empty();
    let screener = RulesetScreener {
        rules: &rules,
        acceptances: &acceptances,
        names: &names,
        mode: ScreenMode::Enforce,
        limits: Limits::default(),
    };

    let out = admission::admit(
        &request(m["spiffe_id"].as_str().unwrap(), card),
        &AdmissionCtx {
            identity: &identity,
            surface: &source,
            card: &card_verifier,
            provenance: &provenance,
            screener: &screener,
            tier_rules: TierRules::default(),
            limits: Limits::default(),
            now: NOW,
        },
    )
    .expect("a fully attested registration must succeed");

    // The claim this file exists to make.
    assert_eq!(
        out.entity.posture,
        Posture::Attested,
        "stages: {:#?}",
        out.stages
    );
    assert_eq!(out.entity.reattested_at, NOW, "an attested party is dated");

    // And no stage was skipped. A skipped stage that left the posture attested would
    // be the worst possible pass — it is the shape of every defect in this repository's
    // history, so it is asserted rather than assumed from the posture.
    for stage in &out.stages {
        assert!(
            !format!("{stage:?}").contains("Skipped"),
            "a stage was skipped on the happy path: {stage:?}"
        );
    }
    assert_eq!(out.stages.len(), 7, "seven stages ran: {:#?}", out.stages);

    // The identity came from the token, not from the request.
    assert_eq!(out.entity.id.as_str(), m["spiffe_id"].as_str().unwrap());
    assert!(!out.entity.pin.is_empty(), "the card was pinned");
}

// ===========================================================================
// Each stage must actually gate — one negative per verifier
// ===========================================================================

#[test]
fn a_token_minted_for_another_audience_is_refused() {
    // The check that stops a JWT-SVID issued to a different service being replayed
    // here. `set_audience` makes it real; an empty audience would make it vacuous,
    // which `attest` refuses separately.
    let rig = Rig::new();
    let m = manifest();
    let identity = JwtSvidIdentity {
        keys: &rig.bundle,
        audience: "warden-connect://control-plane/emea".to_string(),
        token: svid(),
        leeway: 60,
        now: NOW,
    };
    let err = identity_only(&rig, &identity, m["spiffe_id"].as_str().unwrap()).unwrap_err();
    assert_eq!(err.code(), Code::IDENTITY_UNVERIFIABLE);
}

#[test]
fn a_token_that_authenticates_a_different_party_is_refused() {
    // The binding. Everything else proves a valid token was presented; only this
    // proves it belongs to the party being registered.
    let rig = Rig::new();
    let identity = JwtSvidIdentity {
        keys: &rig.bundle,
        audience: rig.audience.clone(),
        token: svid(),
        leeway: 60,
        now: NOW,
    };
    let err =
        identity_only(&rig, &identity, "spiffe://org/ns/agents/sa/somebody-else").unwrap_err();
    assert_eq!(err.code(), Code::IDENTITY_UNVERIFIABLE);
    assert!(
        err.detail().contains("registration claims"),
        "{}",
        err.detail()
    );
}

#[test]
fn the_three_roles_are_three_keys_and_cannot_be_confused() {
    // The reason the fixtures use three keypairs. If the card verifier would accept
    // the SPIFFE bundle key, a deployment that configured one key everywhere would
    // appear to work — and an agent able to mint its own SVID could then sign its own
    // card.
    let rig = Rig::new();
    let m = manifest();
    let identity = JwtSvidIdentity {
        keys: &rig.bundle,
        audience: rig.audience.clone(),
        token: svid(),
        leeway: 60,
        now: NOW,
    };
    // The card signer's slot, holding the *bundle* key under the card's kid.
    let mut wrong = IssuerKeys::new();
    wrong
        .add_ec_pem(
            "card-signer-1",
            &read("spiffe-bundle.pub.pem"),
            Algorithm::ES256,
        )
        .unwrap();
    let card_verifier = JwksCardVerifier {
        keys: &wrong,
        require_signature: true,
    };
    let provenance = DsseProvenanceVerifier {
        keys: &rig.builder_keys,
        envelopes: vec![envelope()],
        artifact_digest: Some(digest()),
        allowed_builders: rig.builders.clone(),
    };
    let card = card();
    let source = InlineSurface::new(SurfaceKind::A2aCard, card.clone());
    let screener = NoScreening;
    let err = admission::admit(
        &request(m["spiffe_id"].as_str().unwrap(), card),
        &AdmissionCtx {
            identity: &identity,
            surface: &source,
            card: &card_verifier,
            provenance: &provenance,
            screener: &screener,
            tier_rules: TierRules::default(),
            limits: Limits::default(),
            now: NOW,
        },
    )
    .unwrap_err();
    assert_eq!(err.code(), Code::CARD_SIGNATURE_INVALID);
}

#[test]
fn provenance_for_a_different_artifact_does_not_vouch_for_this_one() {
    // A DSSE envelope that verifies is not the same as a DSSE envelope that says
    // anything about the thing being admitted. The subject digest is the binding, and
    // without it the statement vouches for nothing in particular.
    let rig = Rig::new();
    let m = manifest();
    let provenance = DsseProvenanceVerifier {
        keys: &rig.builder_keys,
        envelopes: vec![envelope()],
        artifact_digest: Some(
            "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        ),
        allowed_builders: rig.builders.clone(),
    };
    let out = full(&rig, m["spiffe_id"].as_str().unwrap(), provenance);
    match out {
        Ok(o) => assert_ne!(
            o.entity.posture,
            Posture::Attested,
            "provenance bound to another artifact must not attest this one"
        ),
        Err(e) => assert_eq!(e.code(), Code::PROVENANCE_UNVERIFIABLE),
    }
}

#[test]
fn a_builder_nobody_allowed_does_not_attest() {
    let rig = Rig::new();
    let m = manifest();
    let mut only_someone_else = BTreeSet::new();
    only_someone_else.insert("https://builds.example/other-pipeline.yml".to_string());
    let provenance = DsseProvenanceVerifier {
        keys: &rig.builder_keys,
        envelopes: vec![envelope()],
        artifact_digest: Some(digest()),
        allowed_builders: only_someone_else,
    };
    let out = full(&rig, m["spiffe_id"].as_str().unwrap(), provenance);
    match out {
        Ok(o) => assert_ne!(o.entity.posture, Posture::Attested),
        Err(e) => assert_eq!(e.code(), Code::PROVENANCE_UNVERIFIABLE),
    }
}

#[test]
fn an_unsigned_card_is_refused_when_a_signature_is_required() {
    let rig = Rig::new();
    let m = manifest();
    let mut stripped = card();
    stripped.as_object_mut().unwrap().remove("signatures");

    let identity = JwtSvidIdentity {
        keys: &rig.bundle,
        audience: rig.audience.clone(),
        token: svid(),
        leeway: 60,
        now: NOW,
    };
    let card_verifier = JwksCardVerifier {
        keys: &rig.card_keys,
        require_signature: true,
    };
    let provenance = DsseProvenanceVerifier {
        keys: &rig.builder_keys,
        envelopes: vec![envelope()],
        artifact_digest: Some(digest()),
        allowed_builders: rig.builders.clone(),
    };
    let source = InlineSurface::new(SurfaceKind::A2aCard, stripped.clone());
    let screener = NoScreening;
    let err = admission::admit(
        &request(m["spiffe_id"].as_str().unwrap(), stripped),
        &AdmissionCtx {
            identity: &identity,
            surface: &source,
            card: &card_verifier,
            provenance: &provenance,
            screener: &screener,
            tier_rules: TierRules::default(),
            limits: Limits::default(),
            now: NOW,
        },
    )
    .unwrap_err();
    assert_eq!(err.code(), Code::CARD_SIGNATURE_INVALID);
}

#[test]
fn one_flipped_bit_anywhere_in_the_material_stops_attestation() {
    // The blunt instrument, and the one that would catch a verifier that parsed the
    // material and forgot to check the signature over it.
    let rig = Rig::new();
    let m = manifest();
    let good = svid();

    // The signature segment, one bit different.
    let (head, sig) = good.rsplit_once('.').unwrap();
    let mut bytes = sig.as_bytes().to_vec();
    bytes[0] = if bytes[0] == b'A' { b'B' } else { b'A' };
    let tampered = format!("{head}.{}", String::from_utf8(bytes).unwrap());

    let identity = JwtSvidIdentity {
        keys: &rig.bundle,
        audience: rig.audience.clone(),
        token: tampered,
        leeway: 60,
        now: NOW,
    };
    let err = identity_only(&rig, &identity, m["spiffe_id"].as_str().unwrap()).unwrap_err();
    assert_eq!(err.code(), Code::IDENTITY_UNVERIFIABLE);
}

#[test]
fn an_expired_svid_is_refused_rather_than_carried() {
    // The same fixture, two hours later. Its `exp` is NOW + 3600, and this is the
    // property that a wall-clock verifier could not express at all: one token, judged
    // at an instant the test chooses.
    let rig = Rig::new();
    let m = manifest();
    let later = NOW + 2 * 3600;
    let identity = JwtSvidIdentity {
        keys: &rig.bundle,
        audience: rig.audience.clone(),
        token: svid(),
        leeway: 60,
        now: later,
    };
    let card = card();
    let source = InlineSurface::new(SurfaceKind::A2aCard, card.clone());
    let screener = NoScreening;
    let provenance = DsseProvenanceVerifier {
        keys: &rig.builder_keys,
        envelopes: vec![envelope()],
        artifact_digest: Some(digest()),
        allowed_builders: rig.builders.clone(),
    };
    let err = admission::admit(
        &request(m["spiffe_id"].as_str().unwrap(), card),
        &AdmissionCtx {
            identity: &identity,
            surface: &source,
            card: &card_verifier_for(&rig),
            provenance: &provenance,
            screener: &screener,
            tier_rules: TierRules::default(),
            limits: Limits::default(),
            now: later,
        },
    )
    .unwrap_err();
    assert_eq!(err.code(), Code::IDENTITY_UNVERIFIABLE);
    assert!(err.detail().contains("expired at"), "{}", err.detail());
}

// ---------------------------------------------------------------------------
// Scaffolding
// ---------------------------------------------------------------------------

fn card_verifier_for<'a>(rig: &'a Rig) -> JwksCardVerifier<'a> {
    JwksCardVerifier {
        keys: &rig.card_keys,
        require_signature: true,
    }
}

/// Admit with everything real except the parts a stage-1 test does not reach.
fn identity_only(
    rig: &Rig,
    identity: &dyn wc_control::admission::IdentityVerifier,
    claim_id: &str,
) -> wc_core::error::Result<admission::AdmissionOutcome> {
    let card = card();
    let source = InlineSurface::new(SurfaceKind::A2aCard, card.clone());
    let screener = NoScreening;
    let provenance = DsseProvenanceVerifier {
        keys: &rig.builder_keys,
        envelopes: vec![envelope()],
        artifact_digest: Some(digest()),
        allowed_builders: rig.builders.clone(),
    };
    admission::admit(
        &request(claim_id, card),
        &AdmissionCtx {
            identity,
            surface: &source,
            card: &card_verifier_for(rig),
            provenance: &provenance,
            screener: &screener,
            tier_rules: TierRules::default(),
            limits: Limits::default(),
            now: NOW,
        },
    )
}

/// Admit with a caller-supplied provenance verifier and everything else real.
fn full(
    rig: &Rig,
    claim_id: &str,
    provenance: DsseProvenanceVerifier<'_>,
) -> wc_core::error::Result<admission::AdmissionOutcome> {
    let identity = JwtSvidIdentity {
        keys: &rig.bundle,
        audience: rig.audience.clone(),
        token: svid(),
        leeway: 60,
        now: NOW,
    };
    let card = card();
    let source = InlineSurface::new(SurfaceKind::A2aCard, card.clone());
    let screener = NoScreening;
    admission::admit(
        &request(claim_id, card),
        &AdmissionCtx {
            identity: &identity,
            surface: &source,
            card: &card_verifier_for(rig),
            provenance: &provenance,
            screener: &screener,
            tier_rules: TierRules::default(),
            limits: Limits::default(),
            now: NOW,
        },
    )
}

// ===========================================================================
// Interop: an attestation produced by cosign, not by us
// ===========================================================================
//
// Everything in `fixtures/attest/` is minted by `scripts/gen-attest-fixtures.py`, which is an
// independent *reading* of SPIFFE/DSSE/in-toto and catches disagreements about what the specs
// say. It cannot catch a disagreement about what the ecosystem actually emits — and that is
// where stage 4 was broken.
//
// `fixtures/cosign/` is real cosign v3.1.3 output. Adding it found two defects, either of
// which alone made `DsseProvenanceVerifier` **reject every real cosign attestation**:
//
//   · cosign omits `keyid`, which DSSE calls an optional unauthenticated hint. The verifier
//     required it and refused with "signature has no keyid".
//   · cosign signs ECDSA as **DER**. The verifier expected raw `R‖S`, as JWS uses. DSSE
//     specifies no encoding, so it accepted exactly one dialect of a two-dialect format —
//     its own.

const COSIGN_ENVELOPE: &str = include_str!("../../../fixtures/cosign/provenance.dsse.json");
const COSIGN_PUB: &[u8] = include_bytes!("../../../fixtures/cosign/cosign.pub.pem");
const COSIGN_DIGEST: &str =
    "sha256:145325314c684ce617a7806cd03fd87338c5e365d3ef6aa1b61b4143aaeace7b";
const COSIGN_BUILDER: &str =
    "https://github.com/vijayvedula/warden-connect/.github/workflows/release.yml";

fn cosign_keys() -> wc_core::contract::IssuerKeys {
    let mut keys = wc_core::contract::IssuerKeys::new();
    keys.add_ec_pem("cosign-1", COSIGN_PUB, wc_core::contract::Algorithm::ES256)
        .expect("cosign's public key is a P-256 SPKI PEM");
    keys
}

/// A verifier over the real cosign envelope, with the builder and digest it names.
fn cosign_verifier<'a>(
    keys: &'a wc_core::contract::IssuerKeys,
    digest: Option<&str>,
    builder: &str,
) -> wc_control::attest::DsseProvenanceVerifier<'a> {
    wc_control::attest::DsseProvenanceVerifier {
        keys,
        envelopes: vec![serde_json::from_str(COSIGN_ENVELOPE).expect("the fixture is JSON")],
        artifact_digest: digest.map(str::to_string),
        allowed_builders: [builder.to_string()].into_iter().collect(),
    }
}

#[test]
fn a_real_cosign_attestation_verifies() {
    // The end the whole fixture exists for. If this fails, stage 4 works only against
    // envelopes we produced ourselves — which is what P0 #3 warned about in the first place:
    // *a fixture produced by the same code that reads it proves only that the code agrees
    // with itself.*
    let keys = cosign_keys();
    let verifier = cosign_verifier(&keys, Some(COSIGN_DIGEST), COSIGN_BUILDER);
    let envelope = verifier.envelopes[0].clone();

    let (_bindings, _refs, method) = verifier
        .verify_envelope(&envelope)
        .expect("a real cosign envelope must verify");

    assert!(
        method.contains("subject matched"),
        "the digest binds the statement to the artifact: {method}"
    );
    assert!(method.contains("builder allowed"), "{method}");
    // Attributed to the key that actually verified it, even though the envelope named none.
    assert!(method.contains("cosign-1"), "{method}");
}

#[test]
fn the_cosign_envelope_really_does_omit_keyid_and_use_der() {
    // Guards the *premise* of the two fixes. If a future cosign starts emitting a keyid, or
    // raw `R‖S`, this fixture stops exercising the paths it was added for — and the test above
    // would keep passing while the interop coverage quietly evaporated.
    let envelope: serde_json::Value = serde_json::from_str(COSIGN_ENVELOPE).unwrap();
    let sig = &envelope["signatures"][0];

    assert!(
        sig.get("keyid").is_none() || sig["keyid"].as_str() == Some(""),
        "the fixture is meant to have no keyid: {sig}"
    );

    use base64::Engine as _;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(sig["sig"].as_str().unwrap())
        .unwrap();
    assert_eq!(
        raw.first(),
        Some(&0x30),
        "the fixture is meant to carry a DER signature, not raw R||S"
    );
    assert_ne!(raw.len(), 64, "64 bytes would be raw R||S and not DER");
}

#[test]
fn a_cosign_attestation_for_a_different_artifact_does_not_bind() {
    // The subject digest is what binds a statement to an artifact; without it the envelope
    // vouches for nothing in particular. Accepting DER and a missing keyid must not have
    // loosened that.
    let keys = cosign_keys();
    let other = format!("sha256:{}", "00".repeat(32));
    let verifier = cosign_verifier(&keys, Some(&other), COSIGN_BUILDER);
    let envelope = verifier.envelopes[0].clone();

    match verifier.verify_envelope(&envelope) {
        Err(e) => assert_eq!(e.code(), Code::PROVENANCE_UNVERIFIABLE),
        Ok((_, _, method)) => assert!(
            !method.contains("subject matched"),
            "a statement about another artifact must not report a matched subject: {method}"
        ),
    }
}

#[test]
fn a_cosign_attestation_from_an_untrusted_builder_does_not_pass() {
    let keys = cosign_keys();
    let verifier = cosign_verifier(&keys, Some(COSIGN_DIGEST), "https://builder.example/other");
    let envelope = verifier.envelopes[0].clone();

    match verifier.verify_envelope(&envelope) {
        Err(e) => assert_eq!(e.code(), Code::PROVENANCE_UNVERIFIABLE),
        Ok((_, _, method)) => assert!(
            !method.contains("builder allowed"),
            "an untrusted builder must not read as allowed: {method}"
        ),
    }
}

#[test]
fn an_untrusted_key_is_still_refused_when_the_envelope_names_no_keyid() {
    // The security question the "try every trusted key" fallback raises, asserted directly:
    // trying all *configured* keys must not become trying *any* key. An attacker omitting the
    // hint may only select among keys the verifier already trusts.
    let mut wrong = wc_core::contract::IssuerKeys::new();
    wrong
        .add_ec_pem(
            "not-cosign",
            include_bytes!("../../../fixtures/keys/test_issuer_es256_pub.pem"),
            wc_core::contract::Algorithm::ES256,
        )
        .unwrap();
    let verifier = cosign_verifier(&wrong, Some(COSIGN_DIGEST), COSIGN_BUILDER);
    let envelope = verifier.envelopes[0].clone();

    let err = verifier
        .verify_envelope(&envelope)
        .expect_err("a key we do not trust must not verify it");
    assert_eq!(err.code(), Code::PROVENANCE_UNVERIFIABLE);
}

// ===========================================================================
// Interop: a JWT-SVID minted by SPIRE, not by us
// ===========================================================================
//
// The same argument as `fixtures/cosign/` one stage earlier. `fixtures/attest/jwt-svid.token`
// is minted by `scripts/gen-attest-fixtures.py` from the SPIFFE and JOSE spec text, so it can
// only catch a disagreement about what the specs *say*. `fixtures/spire/` is the output of a
// real SPIRE 1.15.2 server and agent, which is the only thing that catches a disagreement
// about what an issuer actually emits.
//
// Two things a reader should know about the shape, because they are the parts a verifier is
// most likely to get wrong (see `a_real_spire_svid_omits_iss_and_nbf`):
//
//   · **there is no `iss` claim.** SPIRE does not emit one; the trust domain is carried in
//     `sub`. A verifier with `set_issuer(...)` would reject every real SVID.
//   · **`aud` is an array**, even for one audience.
//
// The trust bundle is checked in exactly as `spire-server bundle show -format spiffe` printed
// it — including the `x509-svid` key that has no `kid` — because that whole document is what an
// operator will paste, and `add_jwks` has to survive it rather than require it be pre-filtered.

fn spire_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/spire")
}

fn spire_read(name: &str) -> String {
    let path = spire_dir().join(name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{}: {e}\n\nSee fixtures/spire/README.md.", path.display()))
}

fn spire_manifest() -> Value {
    serde_json::from_str(&spire_read("manifest.json")).unwrap()
}

/// The trust bundle, loaded the way an operator would: the whole SPIFFE bundle, unedited.
fn spire_bundle() -> (IssuerKeys, wc_core::contract::JwksReport) {
    let mut keys = IssuerKeys::new();
    let report = keys
        .add_jwks(&spire_read("bundle.spiffe.json"))
        .expect("SPIRE's own trust bundle must load");
    (keys, report)
}

fn spire_identity<'a>(
    keys: &'a IssuerKeys,
    token: &str,
    audience: &str,
    now: u64,
) -> JwtSvidIdentity<'a> {
    JwtSvidIdentity {
        keys,
        audience: audience.to_string(),
        token: token.trim().to_string(),
        leeway: 60,
        now,
    }
}

#[test]
fn a_real_spire_jwt_svid_authenticates_the_party_it_names() {
    // Stage 1 against a real issuer. Until this test existed, every SVID the verifier had
    // ever seen was minted by a script in this repository.
    let m = spire_manifest();
    let (keys, _) = spire_bundle();
    let identity = spire_identity(
        &keys,
        &spire_read("jwt-svid.token"),
        m["audience"].as_str().unwrap(),
        m["iat"].as_u64().unwrap(),
    );
    let proof = identity
        .verify_identity(&request(m["spiffe_id"].as_str().unwrap(), card()))
        .expect("a real SPIRE JWT-SVID must authenticate");
    assert_eq!(proof.id.as_str(), m["spiffe_id"].as_str().unwrap());
    assert!(
        proof.verified,
        "a signature-checked SVID is not a mere assertion"
    );
    assert!(
        proof.method.contains(m["jwt_svid_kid"].as_str().unwrap()),
        "the proof should name the bundle key that verified it: {}",
        proof.method
    );
}

#[test]
fn the_whole_spiffe_bundle_loads_and_says_what_it_could_not_use() {
    // `bundle show -format spiffe` returns the x509-svid signing key beside the jwt-svid one,
    // and the x509 key has no `kid`. Both facts have to be true for this fixture to be
    // exercising anything, so they are asserted rather than assumed.
    let m = spire_manifest();
    let doc: Value = serde_json::from_str(&spire_read("bundle.spiffe.json")).unwrap();
    let uses: Vec<&str> = doc["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k["use"].as_str().unwrap())
        .collect();
    assert_eq!(
        uses,
        vec!["x509-svid", "jwt-svid"],
        "the fixture's shape changed"
    );
    assert!(
        doc["keys"][0]["kid"].is_null(),
        "the x509-svid key is meant to have no kid — that is the case this test covers"
    );

    let (keys, report) = spire_bundle();
    assert_eq!(
        report.added,
        vec![m["jwt_svid_kid"].as_str().unwrap().to_string()],
        "exactly the JWT signing key should become trusted"
    );
    assert_eq!(report.skipped, vec!["no kid".to_string()]);
    assert!(
        !report.is_complete(),
        "a bundle with an unusable key is not complete, and an operator should be told"
    );
    assert_eq!(
        keys.kids(),
        report.added,
        "trusted kids and the report must agree"
    );
}

#[test]
fn a_real_spire_token_minted_for_another_audience_is_refused() {
    // A2, against real material: the same agent, the same bundle, an SVID SPIRE minted for
    // the EMEA control plane presented to the APAC one.
    let m = spire_manifest();
    let (keys, _) = spire_bundle();
    let identity = spire_identity(
        &keys,
        &spire_read("jwt-svid-other-audience.token"),
        m["audience"].as_str().unwrap(),
        m["iat"].as_u64().unwrap(),
    );
    let err = identity
        .verify_identity(&request(m["spiffe_id"].as_str().unwrap(), card()))
        .expect_err("an SVID for another control plane must not authenticate here");
    assert_eq!(err.code(), Code::IDENTITY_UNVERIFIABLE);

    // And it is a real token, not a broken one: it verifies against the audience it was
    // minted for. Otherwise this test would pass on a corrupt fixture.
    let other = spire_identity(
        &keys,
        &spire_read("jwt-svid-other-audience.token"),
        m["other_audience"].as_str().unwrap(),
        m["iat"].as_u64().unwrap(),
    );
    other
        .verify_identity(&request(m["spiffe_id"].as_str().unwrap(), card()))
        .expect("the same token must verify for its own audience");
}

#[test]
fn a_real_spire_svid_omits_iss_and_nbf() {
    // Not a test of our code — a test of the assumption our code is allowed to make. SPIRE
    // emits neither claim, so any future `set_required_spec_claims(["iss"])` or `nbf` floor
    // would reject every real SVID while every fixture in `fixtures/attest/` kept passing.
    // This test is here to fail first, with the reason attached.
    let token = spire_read("jwt-svid.token");
    let claims_b64 = token
        .trim()
        .split('.')
        .nth(1)
        .expect("a JWS has three parts");
    let claims: Value =
        serde_json::from_slice(&base64_url_decode(claims_b64)).expect("the claims are JSON");

    assert!(
        claims.get("iss").is_none(),
        "SPIRE grew an `iss` claim: {claims}"
    );
    assert!(
        claims.get("nbf").is_none(),
        "SPIRE grew an `nbf` claim: {claims}"
    );
    assert!(
        claims["aud"].is_array(),
        "`aud` is an array even for one audience: {claims}"
    );
    for required in ["sub", "aud", "exp", "iat"] {
        assert!(
            claims.get(required).is_some(),
            "SPIRE dropped `{required}`: {claims}"
        );
    }
}

#[test]
fn a_real_spire_svid_is_refused_once_its_own_exp_passes() {
    // SPIRE's default JWT-SVID lifetime is short by design, so the checked-in token is
    // expired against the wall clock and always will be. Judged at an instant it chooses,
    // the same token is accepted before `exp` and refused after — which is the whole reason
    // `JwtSvidIdentity::now` is injected rather than read from the system.
    let m = spire_manifest();
    let (keys, _) = spire_bundle();
    let exp = m["exp"].as_u64().unwrap();
    let id = m["spiffe_id"].as_str().unwrap();

    spire_identity(
        &keys,
        &spire_read("jwt-svid.token"),
        m["audience"].as_str().unwrap(),
        exp - 60,
    )
    .verify_identity(&request(id, card()))
    .expect("valid a minute before exp");

    let err = spire_identity(
        &keys,
        &spire_read("jwt-svid.token"),
        m["audience"].as_str().unwrap(),
        exp + 3600,
    )
    .verify_identity(&request(id, card()))
    .expect_err("an hour past exp it must be refused, not carried");
    assert_eq!(err.code(), Code::IDENTITY_UNVERIFIABLE);
    assert!(err.detail().contains("expired at"), "{}", err.detail());
}

#[test]
fn a_real_spire_svid_does_not_vouch_for_a_party_it_does_not_name() {
    // The binding stage 1 exists for, against real material: cryptographically valid, and
    // presented for somebody else.
    let m = spire_manifest();
    let (keys, _) = spire_bundle();
    let identity = spire_identity(
        &keys,
        &spire_read("jwt-svid.token"),
        m["audience"].as_str().unwrap(),
        m["iat"].as_u64().unwrap(),
    );
    let err = identity
        .verify_identity(&request(
            "spiffe://example.org/ns/agents/sa/somebody-else",
            card(),
        ))
        .expect_err("a valid SVID must not attest a party it does not name");
    assert_eq!(err.code(), Code::IDENTITY_UNVERIFIABLE);
    assert!(
        err.detail().contains("registration claims"),
        "the refusal should name the binding that failed: {}",
        err.detail()
    );
}

/// base64url without padding, for reading a JWS payload in a test.
fn base64_url_decode(s: &str) -> Vec<u8> {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .expect("a JWS segment is base64url")
}
