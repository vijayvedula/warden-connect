//! warden-connect shared types.
//!
//! This crate is the vocabulary every other crate speaks: error codes, the
//! domain model, the canonical surface serialisation (`wcs1`), and the
//! connection contract. It holds no I/O and no policy — which is why it can be
//! unit-tested exhaustively and why `wc-mediator` can link it on the hot path
//! without dragging in a control plane.
//!
//! See `docs/08-lld.md` §8.4 for the module inventory.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod canon;
pub mod contract;
pub mod error;
pub mod model;
pub mod util;
