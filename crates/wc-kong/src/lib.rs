//! A C ABI over [`warden_connect_gateway::Filter`], for a Kong plugin to drive over LuaJIT FFI.
//!
//! # Why FFI and not a plugin server
//!
//! Kong can run an external plugin in Go, Python or JS over a MessagePack-RPC socket. Every one
//! of those routes adds a process and an IPC hop, and none of them can reuse the contract
//! verifier — so the plugin would either call back into a Rust daemon (two processes, two
//! protocols) or reimplement JWS, EC and canonicalisation (a second verifier in the estate, and
//! the one place a divergence would be invisible). Kong already embeds LuaJIT, whose FFI calls
//! a C ABI at near-native cost, so the decision stays in this library and the plugin stays
//! wiring.
//!
//! # The boundary rules
//!
//! | Rule | Why |
//! |---|---|
//! | every entry point is wrapped in `catch_unwind` | a panic unwinding into LuaJIT is undefined behaviour |
//! | Rust allocates every out buffer; Lua calls [`wc_out_free`] | one allocator owns the memory |
//! | a null pointer is [`WC_ERR_BADARG`], never a dereference | Lua can and will pass one |
//! | an unknown state is a refusal | the fail-closed rule does not stop at the ABI |
//!
//! # Panic strategy
//!
//! `catch_unwind` is the safety boundary, and it does nothing under `panic = "abort"` — the
//! process dies instead, taking the nginx worker with it. That would be a control which reads
//! as configured and is not there, so it is a build error rather than a runtime surprise.

#![deny(missing_docs)]

#[cfg(panic = "abort")]
compile_error!(
    "wc-kong requires panic=unwind: catch_unwind is the FFI safety boundary, and under \
     panic=abort a panic in the filter takes down the nginx worker instead of refusing one call"
);

pub mod abi;
pub mod config;

pub use abi::*;

/// Unix time, seconds. A plain `fn` because that is what `ContractSet` takes.
#[must_use]
pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}
