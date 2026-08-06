//! Test-only crate. See `tests/`.
//!
//! Deliberately empty: this crate exists so the end-to-end tier can depend on
//! both the control plane and the data plane at once. No shipped crate does, and
//! adding that dependency for testing convenience would undo the independence the
//! two-crate split exists to provide (§8.3).
