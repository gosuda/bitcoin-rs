//! Optional Bitcoin Core-compatible USDT tracepoints.
//!
//! Every function in this module is a no-op unless the consuming binary is
//! built with the `usdt` feature enabled. When it is, the probes carry
//! Bitcoin Core's provider names (`validation`, `mempool`, `net`), probe
//! names, and argument layout — the crate-root `probes.d` is the generator
//! input and the compatibility table; see `docs/tracing.md`.
//!
//! Hot-path semantics mirror Bitcoin Core's `src/util/trace.h`: each emission
//! site passes a `prepare` closure that *materialises* the probe arguments,
//! and the closure is only invoked when a consumer (bpftrace, BCC, `DTrace`,
//! …) has raised the probe's semaphore. With the feature on and nothing
//! attached the cost is one volatile semaphore load per probe site; with the
//! feature off every call is an empty function body and the closure is
//! dropped without running.

// The usdt generator's probe macros cast their arguments to usize and
// define an inline type-check item inside their expansion; that output is
// not ours to reshape, so allow its lint set for the whole module.
#![allow(
    clippy::items_after_statements,
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

mod generated {
    // Raw generated probe macros, one generated module per provider. The
    // generator names a module after each provider, so this private module
    // keeps the generated `validation`/`mempool`/`net` modules out of the
    // crate root where the public wrappers live. The provider definition
    // lives at the package root next to `Cargo.toml`, where the `usdt`
    // macro resolves it.
    #[cfg(feature = "usdt")]
    usdt::dtrace_provider!("probes.d");
}

/// Buffer address for the emitter's by-value pointer arguments.
///
/// Core passes hash and message buffers as pointers by value (`8@%reg`); the
/// `usdt` crate's `uint8_t*` declaration would instead emit a dereferencing
/// operand (`8@(%reg)`), so `probes.d` declares byte-buffer arguments
/// `uint64_t` and the call sites below feed it the address.
#[cfg(feature = "usdt")]
fn address_of(buffer: *const u8) -> u64 {
    u64::try_from(buffer.addr()).unwrap_or(0)
}

/// Prepared arguments of `net:inbound_message` / `net:outbound_message`.
///
/// `(node_id, addr, conn_type, msg_type, payload_size, payload)`. `payload`
/// must address `payload_size` bytes that outlive the probe call; callers
/// pass the encoded frame's own byte slice.
pub type MessageArgs = (i64, String, String, String, u64, *const u8);

/// Fires `validation:block_connected` if probes are compiled in.
///
/// Arguments follow Bitcoin Core's `validation:block_connected` ABI (see
/// `probes.d` and `docs/tracing.md`): `(block_hash, height, transactions,
/// inputs, sigops_cost, elapsed_ns)`, where `block_hash` must address 32
/// bytes that outlive the probe call; callers pass the hash's own byte
/// array. `prepare` runs only while a consumer is attached.
pub fn block_connected(prepare: impl FnOnce() -> (*const u8, i32, u64, i32, i64, i64)) {
    #[cfg(feature = "usdt")]
    generated::validation::block_connected!(|| {
        let (hash, height, txs, inputs, sigops, elapsed_ns) = prepare();
        (address_of(hash), height, txs, inputs, sigops, elapsed_ns)
    });
    #[cfg(not(feature = "usdt"))]
    drop(prepare);
}

/// Fires `mempool:added` if probes are compiled in.
///
/// Arguments follow Bitcoin Core's `mempool:added` ABI: `(txid, vsize,
/// fee)`, where `txid` must address 32 bytes that outlive the probe call.
/// `prepare` runs only while a consumer is attached.
pub fn added(prepare: impl FnOnce() -> (*const u8, i32, i64)) {
    #[cfg(feature = "usdt")]
    generated::mempool::added!(|| {
        let (txid, vsize, fee) = prepare();
        (address_of(txid), vsize, fee)
    });
    #[cfg(not(feature = "usdt"))]
    drop(prepare);
}

/// Fires `mempool:removed` if probes are compiled in.
///
/// Arguments follow Bitcoin Core's `mempool:removed` ABI: `(txid, reason,
/// vsize, fee, entry_time)`, where `txid` must address 32 bytes that
/// outlive the probe call. `prepare` runs only while a consumer is
/// attached.
pub fn removed(prepare: impl FnOnce() -> (*const u8, &'static str, i32, i64, u64)) {
    #[cfg(feature = "usdt")]
    generated::mempool::removed!(|| {
        let (txid, reason, vsize, fee, entry_time) = prepare();
        (address_of(txid), reason, vsize, fee, entry_time)
    });
    #[cfg(not(feature = "usdt"))]
    drop(prepare);
}

/// Fires `net:inbound_message` if probes are compiled in.
///
/// `prepare` runs only while a consumer is attached.
pub fn inbound_message(prepare: impl FnOnce() -> MessageArgs) {
    #[cfg(feature = "usdt")]
    generated::net::inbound_message!(|| {
        let (node_id, addr, conn_type, msg_type, size, payload) = prepare();
        (
            node_id,
            addr,
            conn_type,
            msg_type,
            size,
            address_of(payload),
        )
    });
    #[cfg(not(feature = "usdt"))]
    drop(prepare);
}

/// Fires `net:outbound_message` if probes are compiled in.
///
/// `prepare` runs only while a consumer is attached.
pub fn outbound_message(prepare: impl FnOnce() -> MessageArgs) {
    #[cfg(feature = "usdt")]
    generated::net::outbound_message!(|| {
        let (node_id, addr, conn_type, msg_type, size, payload) = prepare();
        (
            node_id,
            addr,
            conn_type,
            msg_type,
            size,
            address_of(payload),
        )
    });
    #[cfg(not(feature = "usdt"))]
    drop(prepare);
}

/// Registers statically-defined probes with the platform tracer.
///
/// Must be called once at process start, before any probe site can be
/// discovered by DTrace-family tooling. A no-op without the `usdt` feature.
pub fn register_probes() {
    #[cfg(feature = "usdt")]
    {
        if let Err(error) = usdt::register_probes() {
            tracing::warn!(%error, "usdt probe registration failed; tracepoints may not be visible");
        }
    }
}
