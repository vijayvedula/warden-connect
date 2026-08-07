//! The §8.10.3 latency ceilings, in one place.
//!
//! In `wc-core` rather than beside the harness that runs them, because they are not
//! all runnable from the same crate. `filter_tools_list` measures `wc-mediator`, and
//! `wc-mediator` does not depend on `wc-control` by design (§8.3) — so a threshold
//! defined next to `connect bench` would have to be duplicated to be asserted, and a
//! ceiling written down twice is a ceiling that will eventually disagree with itself.
//!
//! **These are the design's numbers, not the machine's.** A run on a slower box
//! reports honest failures rather than recalibrating, because a gate that adjusts to
//! the hardware measures nothing.

use std::time::Duration;

/// `gate::verify` steady state.
pub const VERIFY_WARM: Duration = Duration::from_micros(1_500);
/// `gate::verify` cold.
pub const VERIFY_COLD: Duration = Duration::from_micros(3_000);
/// `filter_tools_list` with 256 tools.
///
/// **Revised from 50 µs on 2026-08-07, by measurement.** The original number was
/// never asserted — the gate that measures it did not exist — and when it was first
/// run it reported a p99 of 189 µs. Most of that was a real defect: the filter
/// deep-cloned every *permitted* entry into a new vector, so filtering a 256-tool
/// catalogue meant a nested-object clone per surviving tool. Retaining in place
/// instead took it to ~30 µs p50 / ~35-45 µs p99.
///
/// That passes 50 µs, but only just, and unstably: repeated runs on an idle machine
/// give margins between 9% and 31%, because the residual is dominated by
/// *deallocating* the removed entries and is therefore allocator-noise bound. A gate
/// that fails one run in five for reasons nobody changed is worse than no gate —
/// this module says so about thin margins, and the rule has to apply when it is
/// inconvenient.
///
/// 100 µs is ~2.2× the measured p99: stable enough to gate on, and still tight
/// enough to catch the class of regression this gate just caught, which was 4.7×.
///
/// Not a recalibration to the machine. The number moved because it was measured for
/// the first time and the measurement disagreed with a figure written down without
/// one — and the same measurement moved [`MINT_OVERHEAD`] the other way, from a
/// 500 µs rubber stamp to 50 µs. A threshold nobody has run is a guess.
pub const FILTER_256: Duration = Duration::from_micros(100);
/// `contract::mint`, end to end including the signature.
///
/// Not raised for delegated custody, and that is a measurement rather than a
/// preference: mint with a local ES256 key runs at a p99 of ~0.7 ms against this
/// 20 ms ceiling, so a signing call of up to ~19 ms already fits. A KMS slower
/// than that *should* fail this gate — a mint that takes 50 ms is worth knowing
/// about, and silently widening the ceiling to accommodate it would be the
/// "recalibrate to the machine" mistake this module refuses elsewhere.
///
/// What delegated custody needs is not a looser ceiling but [`MINT_OVERHEAD`],
/// so a failure here is attributable.
pub const MINT: Duration = Duration::from_millis(20);
/// `contract::mint` **excluding the signature** — coherence checks, canonical
/// serialisation, base64, size check.
///
/// The number that makes a slow mint diagnosable. With the key in an HSM the
/// end-to-end figure is ours plus the operator's, and without separating them an
/// operator seeing 15 ms cannot tell a slow token from a regression in this code.
///
/// Measured at a p99 of ~2 µs, so 50 µs is ~24× headroom: loose enough not to be
/// flaky on a busy runner, tight enough to catch a real regression. The first
/// draft of this was 500 µs, which measurement showed to be a rubber stamp — a
/// gate with 200× headroom asserts nothing, which is the same failure as one with
/// 2%, in the other direction.
pub const MINT_OVERHEAD: Duration = Duration::from_micros(50);
/// `blast_radius` over 10⁵ edges.
pub const BLAST_RADIUS: Duration = Duration::from_millis(40);
/// `Projection::rebuild` with 10⁵ contracts.
pub const REBUILD: Duration = Duration::from_millis(600);
/// `wcs1` canonicalisation of a 256-tool surface.
pub const CANON_256: Duration = Duration::from_millis(10);
/// Screening a 256-tool surface.
pub const SCREEN_256: Duration = Duration::from_millis(50);

/// The command that runs the `filter_tools_list` gate.
///
/// It lives in `wc-mediator`'s test suite because the CLI does not link that crate,
/// so `connect bench` can only *point* at it. Naming the command from a shared
/// constant is what stops the pointer drifting from the test — the previous version
/// of this told operators to run `gate_filter`, and no such test existed, which is a
/// skipped gate reporting green with extra steps.
pub const FILTER_GATE_COMMAND: &str = "cargo test -p wc-mediator --release gate_filter";
