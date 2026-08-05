//! The warden-connect data plane.
//!
//! An inline mediator that verifies a connection contract, filters the tool
//! catalogue to the contracted surface, and applies the contract's ceilings — as a
//! decorator over Warden core's public `Upstream` trait, so it needs **no change
//! to Warden core** (`docs/08-lld.md` §8.6.1).
//!
//! This is the only crate in the workspace that links `warden`, and that coupling
//! is the deployment model rather than a dependency choice: the mediator composes
//! core's shipped gateway so the data plane adds no second hop. Everything else in
//! warden-connect stays independently adoptable.
//!
//! # The control that matters
//!
//! `tools/list` filtering (§8.6.4). An agent's model cannot be induced to call a
//! tool it was never shown, so reducing the catalogue to the contracted surface is
//! a structural control rather than a probabilistic one. Every other part of this
//! crate exists to make that filter trustworthy.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod cache;
pub mod ceiling;
pub mod client;
pub mod drain;
pub mod filter;
pub mod gate;
pub mod peer;
