//! warden-connect control plane.
//!
//! Runs centrally, off the hot path (`docs/08-lld.md` §7.2). It owns the
//! registry, admission, discovery, contract issuance, posture and exports. A
//! control-plane outage must not take the estate down — but it must not allow
//! new authority either, which is why issuance stops while already-issued
//! contracts keep verifying until they expire.
//!
//! See §8.4 for the module inventory.

// `unsafe` is denied, not forbidden, so that `lock`'s single `flock` call can
// opt in locally with a SAFETY note. Nothing else in the crate may.
#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod admission;
pub mod api;
pub mod assurance;
pub mod attest;
pub mod authority;
pub mod backup;
pub mod bench;
pub mod broker;
pub mod bundle;
pub mod caep;
pub mod chain;
pub mod contain;
pub mod cpolicy;
pub mod custody;
pub mod dist;
pub mod evidence;
pub mod export;
pub mod federate;
pub mod http;
pub mod inventory;
pub mod issuance;
pub mod keys;
pub mod lock;
pub mod need;
pub mod obs;
pub mod offer;
pub mod pipeline;
pub mod registry;
pub mod rekor;
pub mod scm;
pub mod screen;
pub mod signer;
pub mod sink;
pub mod store;
pub mod tenant;
