//! The fuzz targets, runnable on stable (`docs/08-lld.md` §8.15.2).
//!
//! `fuzz/` holds the five libfuzzer targets. They need nightly and `cargo-fuzz`,
//! which means in practice they run when somebody remembers — and a target nobody
//! runs is a target that rots into not compiling, which is how a fuzz directory
//! becomes decoration.
//!
//! So each target's assertions are mirrored here and driven over three input
//! sources on `cargo test`:
//!
//! * the seed corpora in `fuzz/corpus/`, which are the interesting hand-written
//!   inputs — malformed frames, hostile descriptions, a policy with a cycle;
//! * mutations of those seeds, generated deterministically;
//! * pure random bytes, which is the case that catches an index arithmetic slip.
//!
//! This is **not** coverage-guided fuzzing and does not replace it: without
//! instrumentation these inputs will not find the deep path that only a mutation
//! chain reaches. What it does replace is the failure mode where nobody notices
//! the targets stopped compiling. Real campaigns still need:
//!
//! ```sh
//! cargo install cargo-fuzz
//! cd fuzz && cargo +nightly fuzz run parse_contract -- -max_total_time=300
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod harness;

use std::path::PathBuf;
use std::sync::OnceLock;

use serde_json::Value;

use harness::*;
use wc_control::cpolicy::ConnectPolicy;
use wc_control::screen::{
    self, Acceptances, Detector, NameIndex, ScreenCtx, ScreenMode, ScreenRules, Verdict,
};
use wc_core::canon::{self, Limits, SurfaceKind};
use wc_core::contract::{self, RevocationView, VerifyOpts};
use wc_core::model::{EntityId, Tier};
use wc_mediator::cache::Revocations;
use wc_mediator::client::{self, RevocationDelta};

/// Mutations per seed. Small per input, large in aggregate.
const MUTATIONS: usize = 24;
/// Purely random inputs per target.
const RANDOM: usize = 200;

// ---------------------------------------------------------------------------
// Inputs
// ---------------------------------------------------------------------------

fn corpus_dir(target: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fuzz/corpus")
        .join(target)
}

/// The seed corpus for a target, as raw bytes.
fn seeds(target: &str) -> Vec<Vec<u8>> {
    let dir = corpus_dir(target);
    let mut out: Vec<Vec<u8>> = Vec::new();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        panic!("{} is missing — a fuzz target with no seeds tests nothing", dir.display());
    };
    let mut paths: Vec<PathBuf> = entries.filter_map(|e| e.ok().map(|e| e.path())).collect();
    paths.sort();
    for path in paths {
        if path.is_file() {
            out.push(std::fs::read(&path).expect("seed"));
        }
    }
    assert!(!out.is_empty(), "{} is empty", dir.display());
    out
}

/// A deterministic PRNG. Same one as `property.rs`, kept local so neither file
/// silently changes the other's inputs.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Rng {
        Rng(seed | 1)
    }
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next_u64() % n as u64) as usize
        }
    }
    fn byte(&mut self) -> u8 {
        (self.next_u64() & 0xFF) as u8
    }
}

/// Every input a target sees: the seeds, mutations of them, and random noise.
///
/// The mutations are the four libfuzzer does most of its work with — flip, splice,
/// truncate, insert. Not a substitute for coverage feedback, but the same shapes.
fn inputs(target: &str) -> Vec<Vec<u8>> {
    let seeds = seeds(target);
    let mut out = seeds.clone();
    let mut rng = Rng::new(u64::from(target.bytes().map(u32::from).sum::<u32>()) * 0x9E37);

    for seed in &seeds {
        for _ in 0..MUTATIONS {
            let mut m = seed.clone();
            match rng.below(4) {
                0 if !m.is_empty() => {
                    let at = rng.below(m.len());
                    m[at] ^= 1 << rng.below(8);
                }
                1 if !m.is_empty() => m.truncate(rng.below(m.len())),
                2 => {
                    let at = rng.below(m.len() + 1);
                    m.insert(at, rng.byte());
                }
                _ => {
                    // Splice: graft a run from another seed in.
                    let other = &seeds[rng.below(seeds.len())];
                    if !other.is_empty() {
                        let from = rng.below(other.len());
                        let take = rng.below(other.len() - from) + 1;
                        let at = rng.below(m.len() + 1);
                        let tail: Vec<u8> = m.split_off(at);
                        m.extend_from_slice(&other[from..from + take]);
                        m.extend_from_slice(&tail);
                    }
                }
            }
            out.push(m);
        }
    }

    for _ in 0..RANDOM {
        let len = rng.below(256);
        out.push((0..len).map(|_| rng.byte()).collect());
    }
    out
}

/// The corpus plus inputs that only this process can produce.
///
/// A valid artifact is signed with the harness key, for the harness audience, in
/// the harness time window — none of which a checked-in corpus file can know. And
/// the accept path is where the interesting near-misses are: a corpus of inputs
/// that could never be accepted only ever tests the reject path.
fn inputs_with(target: &str, live: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    let mut out = inputs(target);
    let mut rng = Rng::new(0x11FE_u64.wrapping_mul(7));
    for good in &live {
        out.push(good.clone());
        for _ in 0..MUTATIONS * 4 {
            let mut m = good.clone();
            if m.is_empty() {
                continue;
            }
            let at = rng.below(m.len());
            m[at] ^= 1 << rng.below(8);
            out.push(m);
        }
    }
    out
}

fn fuzz_id() -> &'static EntityId {
    static ID: OnceLock<EntityId> = OnceLock::new();
    ID.get_or_init(|| EntityId::new("spiffe://org/ns/tools/sa/fuzz").unwrap())
}

// ===========================================================================
// parse_contract
// ===========================================================================

#[test]
fn fuzz_parse_contract_accepts_nothing_malformed() {
    let keys = verifier();
    let opts = VerifyOpts::new(&keys, MEDIATOR, NOW);
    let mut accepted = 0;

    // A real artifact, so the accept path is exercised and not only the reject path.
    let (estate, issued) = live_contract();
    let live = vec![estate.artifact(issued.record.cid.as_str()).into_bytes()];

    for data in inputs_with("parse_contract", live) {
        let Ok(text) = std::str::from_utf8(&data) else {
            continue;
        };
        let Ok(verified) = contract::verify_artifact(text, &opts) else {
            continue;
        };
        accepted += 1;

        // Anything that verified must be self-consistent, or "verified" means
        // nothing. No panic is the floor; this is the ceiling.
        let p = &verified.payload;
        assert!(p.nbf <= p.exp, "accepted a contract whose window is inverted");
        assert!(NOW >= p.nbf && NOW < p.exp, "accepted a contract outside its window");
        assert_eq!(p.aud, MEDIATOR, "accepted another mediator's contract");
        assert!(!p.cid.as_str().is_empty() && !p.jti.as_str().is_empty());
        assert_ne!(p.caller.id, p.callee.id, "accepted a self-connection");
        assert!(contract::verify_artifact(text, &opts).is_ok(), "verification is not stable");
    }

    // The seed corpus contains one genuinely valid artifact, so a run that accepted
    // nothing means the harness is not reaching the verifier at all.
    assert!(accepted >= 1, "nothing verified — the corpus or the wiring is wrong");
}

// ===========================================================================
// canon_surface
// ===========================================================================

#[test]
fn fuzz_canon_surface_stays_inside_its_limits() {
    let limits = Limits::default();
    let mut canonicalised = 0;

    for data in inputs("canon_surface") {
        let Ok(text) = std::str::from_utf8(&data) else {
            continue;
        };
        let Ok(value) = serde_json::from_str::<Value>(text) else {
            continue;
        };
        for kind in [SurfaceKind::McpTools, SurfaceKind::A2aCard] {
            let Ok(canonical) = canon::canonicalise(kind, fuzz_id(), &value, &limits) else {
                continue;
            };
            canonicalised += 1;
            // The limits are the allocation guarantee, so a success that exceeded
            // them would mean the check is decorative.
            assert!(canonical.items.len() <= limits.max_items);
            assert!(canonical.document.len() <= limits.max_bytes);
            // Idempotent, which is what a pin comparison depends on.
            let again = canon::canonicalise(kind, fuzz_id(), &value, &limits).unwrap();
            assert_eq!(canonical.manifest_hash(), again.manifest_hash());
        }
    }
    assert!(canonicalised >= 2, "the canonicaliser was never reached");
}

// ===========================================================================
// parse_connect_policy
// ===========================================================================

#[test]
fn fuzz_parse_connect_policy_never_panics_and_stays_lintable() {
    let mut parsed = 0;
    for data in inputs("parse_connect_policy") {
        let Ok(text) = std::str::from_utf8(&data) else {
            continue;
        };
        let Ok(policy) = ConnectPolicy::parse(text) else {
            continue;
        };
        parsed += 1;
        // Everything an operator reaches before anyone has read the file.
        let _ = policy.lint();
        let _ = policy.lattice();
        for rule in &policy.rules {
            assert!(rule.decision.as_str().len() > 1);
        }
    }
    assert!(parsed >= 1, "no policy parsed — the corpus is not policy-shaped");
}

// ===========================================================================
// screen_text
// ===========================================================================

#[test]
fn fuzz_screen_text_always_accounts_for_every_detector() {
    let rules = ScreenRules::default();
    let acceptances = Acceptances::default();
    let names = NameIndex::empty();

    for data in inputs("screen_text") {
        // Lossy on purpose: a description is text, and the interesting inputs are
        // the ones that survive a lossy decode with their bidi and zero-width
        // characters intact.
        let text = String::from_utf8_lossy(&data).to_string();
        let surface = serde_json::json!({
            "tools": [{
                "name": "fuzzed_tool",
                "description": text,
                "inputSchema": {"type": "object", "properties": {"arg": {"description": text}}},
            }],
        });
        let Ok(canonical) =
            canon::canonicalise(SurfaceKind::McpTools, fuzz_id(), &surface, &Limits::default())
        else {
            continue;
        };

        for mode in [ScreenMode::Observe, ScreenMode::Flag, ScreenMode::Enforce] {
            for tier in [Tier::ONE, Tier::THREE] {
                let report = screen::screen(
                    &canonical,
                    tier,
                    &ScreenCtx {
                        rules: &rules,
                        acceptances: &acceptances,
                        names: &names,
                        entity: fuzz_id(),
                        mode,
                    },
                );
                // A detector that did not run is a gap, and a report that does not
                // say so is a lie. So every detector must appear in one list or the
                // other — not a count, because S2 legitimately appears in both when
                // the name index is empty: its script half ran and its collision
                // half could not.
                for d in Detector::ALL {
                    assert!(
                        report.ran.contains(&d) || report.skipped.iter().any(|(s, _)| *s == d),
                        "{d:?} was neither run nor reported skipped"
                    );
                }
                assert!(report.skipped.iter().all(|(_, why)| !why.is_empty()),
                        "a skip with no reason is indistinguishable from a clean run");
                // Blocking is earned in code, never granted by input.
                if report.verdict == Verdict::Block {
                    assert!(
                        report.live_hits().iter().any(|h| h.detector.is_blocking()),
                        "a blocking verdict with no blocking-class hit behind it"
                    );
                }
            }
        }
    }
}

// ===========================================================================
// revocation_event
// ===========================================================================

#[test]
fn fuzz_revocation_event_can_never_un_revoke() {
    const ALREADY: &str = "spiffe://org/ns/agents/sa/already-revoked";
    let keys = verifier();
    let mut applied_any = false;

    for data in inputs_with("revocation_event", vec![signed_delta()]) {
        let Ok(text) = std::str::from_utf8(&data) else {
            continue;
        };
        let Ok(delta) = serde_json::from_str::<RevocationDelta>(text) else {
            continue;
        };

        let mut previous = Revocations::new();
        previous.revoke_party(ALREADY);
        let report = client::apply_revocations(&delta, &keys, &previous, 0);
        let set = report.set.clone().expect("apply_revocations always returns a set");

        // Deny-only: no delta, however shaped, may lift an existing revocation.
        assert!(set.party_revoked(ALREADY), "a delta un-revoked a party");
        assert!(report.applied <= delta.events.len(), "more applied than arrived");
        if !report.is_clean() {
            assert!(set.distrusted().is_some(), "a bad pull produced a trusted set");
        } else {
            assert!(set.distrusted().is_none());
        }
        applied_any |= report.applied > 0;
    }
    assert!(applied_any, "no delta ever applied — the corpus is not feed-shaped");
}

// ---------------------------------------------------------------------------
// Live inputs
// ---------------------------------------------------------------------------

fn live_contract() -> (Estate, wc_control::issuance::Issued) {
    let mut e = Estate::new("fuzz-live");
    let agent = e.register(
        "spiffe://org/ns/agents/sa/recon",
        wc_core::model::Kind::Agent,
        "internal.apac-ops",
        &agent_card(),
        SurfaceKind::A2aCard,
        Some("payments-recon"),
    );
    let server = e.register(
        "spiffe://org/ns/tools/sa/payments",
        wc_core::model::Kind::McpServer,
        "internal.payments",
        &surface_of(6),
        SurfaceKind::McpTools,
        Some("payments-core"),
    );
    e.activate(&agent.id);
    e.activate(&server.id);
    let issued = e.connect(&agent.id, &server.id, &["get_balance"], 30 * DAY);
    (e, issued)
}

/// A revocation delta signed with the harness key, so the apply path is reached.
fn signed_delta() -> Vec<u8> {
    let key = signer();
    let mut events = Vec::new();
    for (seq, body) in [
        (1u64, serde_json::json!({"kind": "party", "id": "spiffe://org/ns/agents/sa/recon"})),
        (2u64, serde_json::json!({"kind": "connection", "cid": "conn_00000002"})),
        (3u64, serde_json::json!({"kind": "artifact", "jti": "cx_00000003"})),
    ] {
        let mut event = body;
        event["seq"] = serde_json::json!(seq);
        event["reason"] = serde_json::json!("SOC-FUZZ");
        event["at"] = serde_json::json!(NOW);
        let jws = contract::sign_detached(&event, &key).expect("sign");
        events.push(serde_json::json!({"event": event, "jws": jws, "kid": KID}));
    }
    serde_json::to_vec(&serde_json::json!({
        "head_seq": 3,
        "head_digest": "sha256:aa",
        "events": events,
    }))
    .expect("delta")
}

// ===========================================================================
// The corpora themselves
// ===========================================================================

#[test]
fn every_fuzz_target_has_a_seed_corpus() {
    // A target added without seeds starts from nothing, and the first thing a
    // coverage-guided run does with nothing is spend its budget rediscovering that
    // JSON has braces.
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/Cargo.toml");
    let text = std::fs::read_to_string(&manifest).expect("fuzz/Cargo.toml");
    let targets: Vec<String> = text
        .lines()
        .filter_map(|l| l.strip_prefix("name = \""))
        .filter_map(|l| l.strip_suffix('"'))
        .map(str::to_string)
        .filter(|n| n != "warden-connect-fuzz")
        .collect();
    assert_eq!(targets.len(), 5, "§8.15.2 names five targets, found {targets:?}");
    for target in &targets {
        assert!(!seeds(target).is_empty(), "{target} has no seeds");
    }
}
