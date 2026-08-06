# Fuzz targets

Five targets, mirroring `warden/fuzz` (`docs/08-lld.md` §8.15.2). Each covers one
place where bytes somebody else controls enter the system.

| Target | Input | Beyond no-panic |
|---|---|---|
| `parse_contract` | A contract artifact | **No malformed input is ever accepted** — anything that verifies is re-checked for self-consistency and re-verified |
| `canon_surface` | Arbitrary JSON as a surface | Output stays inside `Limits`, and canonicalisation is idempotent |
| `parse_connect_policy` | Arbitrary TOML | A parsed policy survives `lint` and `lattice`, which run before anyone reads the file |
| `screen_text` | Arbitrary description text | Every detector is accounted for as run or skipped; no input can promote a flag-class finding to blocking |
| `revocation_event` | A revocation delta | No delta can *un*-revoke; a bad pull poisons the set rather than installing a partial one |

## Running a campaign

The crate is excluded from the workspace (`[workspace]` in its `Cargo.toml`), the
same as `warden/fuzz` — it needs nightly and `libfuzzer-sys`, and neither belongs
in the graph a `cargo build` of the workspace resolves.

```sh
cargo install cargo-fuzz                                     # once
cd fuzz
cargo +nightly fuzz run parse_contract -- -max_total_time=300
cargo +nightly fuzz run canon_surface  -- -max_total_time=300
```

`cargo-fuzz` is **not** installed in this checkout, so no coverage-guided campaign
has been run here. The targets compile under `cargo +nightly check --all-targets`,
and that is all that has been verified about them directly.

## What runs on `cargo test`

`crates/wc-e2e/tests/fuzz.rs` mirrors every target's assertions and drives them
over the seed corpora, deterministic mutations of those seeds, and random bytes.

That is not coverage-guided fuzzing and does not replace it: without
instrumentation these inputs will not reach the deep path that only a feedback-
driven mutation chain finds. What it does replace is the failure mode where nobody
notices the targets stopped compiling — a fuzz directory that has quietly rotted
is worse than none, because it reads as coverage.

Two things the mirrored harness does that a checked-in corpus cannot:

* it mints a **real contract** and mutates that, so the accept path is exercised.
  A corpus of inputs that could never be accepted only ever tests the reject path,
  and "no malformed input is accepted" is trivially true of a verifier that
  accepts nothing;
* it signs a **real revocation delta** with the fixture key, for the same reason.

## Corpora

`corpus/<target>/` holds the seeds. `parse_contract`'s are the §8.15.3 conformance
vectors — the same files `connect verify` is the ground truth for — so the two
tiers cannot drift apart. The rest are hand-written: oversize and deeply nested
surfaces, a zone lattice with a cycle, descriptions carrying bidi and zero-width
characters, a feed with a hole in its sequence.

`screen_text` deliberately includes **near misses** as well as attacks: an honest
description that mentions credentials, and prose that discusses prompt injection
as a topic. A detector set that fires on those is a detector set nobody leaves
switched on, so they belong in the corpus as much as the attacks do.
