//! Walk a decision trail and report whether its chain holds.
//!
//! The operator-facing form of this is `connect evidence verify`, which does not exist yet —
//! `wc-cli` does not depend on this crate and adding that edge is a change worth making
//! deliberately rather than in passing. Until then the drills call this, so nothing has to
//! reimplement the chain to check it.
//!
//! Usage: `cargo run -q -p warden-connect-mediator --example evidence-verify -- <path>...`
//! Exits 0 when every trail verifies, 1 otherwise.
#![allow(clippy::unwrap_used, clippy::expect_used)]

fn main() {
    let paths: Vec<String> = std::env::args().skip(1).collect();
    if paths.is_empty() {
        eprintln!("usage: evidence-verify <trail.jsonl>...");
        std::process::exit(2);
    }
    let mut bad = 0;
    for p in &paths {
        match wc_mediator::evidence::verify(p) {
            Ok(head) => println!("ok    {p}  {} row(s), head {}", head.seq, &head.hash[..16]),
            Err(e) => {
                println!("BROKEN {p}");
                println!("       {e}");
                bad += 1;
            }
        }
    }
    std::process::exit(i32::from(bad > 0));
}
