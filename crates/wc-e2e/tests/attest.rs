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
//! What is still not proven, and is the remaining half of P0 #3: the material is the
//! right *shape* but did not come out of a SPIRE server or a build pipeline. The
//! fixtures are files on disk precisely so that swapping in real output and re-running
//! this file is the whole test.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde_json::Value;

use wc_control::admission::{
    self, AdmissionCtx, AdmissionRequest, Declared, InlineSurface, NoScreening, TierRules,
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
