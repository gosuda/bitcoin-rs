//! Bitcoin Core-compatible USDT probes declared in `probes.d`.
//!
//! Feature-off calls are empty; feature-on calls prepare arguments only when
//! an attached consumer raises the semaphore. See `docs/tracing.md`.

// Allow the lint set emitted by the usdt generator's casts and type-check items.
#![allow(
    clippy::items_after_statements,
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

mod generated {
    // Keep generated providers private; the macro loads the package-root definitions.
    #[cfg(feature = "usdt")]
    usdt::dtrace_provider!("probes.d");
}

/// Buffer addresses are passed by value (`8@%reg`), using `uint64_t` in
/// `probes.d` rather than a dereferencing `uint8_t*` (`8@(%reg)`).
#[cfg(feature = "usdt")]
fn address_of(buffer: *const u8) -> u64 {
    u64::try_from(buffer.addr()).unwrap_or(0)
}

/// `(node_id, addr, conn_type, msg_type, payload_size, payload)`.
/// The payload pointer must address `payload_size` bytes for the probe call.
pub type MessageArgs = (i64, String, String, String, u64, *const u8);

/// Emits `(block_hash, height, transactions, inputs, sigops_cost, elapsed_ns)`.
/// The hash pointer must address 32 bytes for the probe call.
pub fn block_connected(prepare: impl FnOnce() -> (*const u8, i32, u64, i32, i64, i64)) {
    #[cfg(feature = "usdt")]
    generated::validation::block_connected!(|| {
        let (hash, height, txs, inputs, sigops, elapsed_ns) = prepare();
        (address_of(hash), height, txs, inputs, sigops, elapsed_ns)
    });
    #[cfg(not(feature = "usdt"))]
    drop(prepare);
}

/// Emits `(txid, vsize, fee)`; the txid pointer must address 32 bytes.
pub fn added(prepare: impl FnOnce() -> (*const u8, i32, i64)) {
    #[cfg(feature = "usdt")]
    generated::mempool::added!(|| {
        let (txid, vsize, fee) = prepare();
        (address_of(txid), vsize, fee)
    });
    #[cfg(not(feature = "usdt"))]
    drop(prepare);
}

/// Emits `(txid, reason, vsize, fee, entry_time)`; txid must address 32 bytes.
pub fn removed(prepare: impl FnOnce() -> (*const u8, &'static str, i32, i64, u64)) {
    #[cfg(feature = "usdt")]
    generated::mempool::removed!(|| {
        let (txid, reason, vsize, fee, entry_time) = prepare();
        (address_of(txid), reason, vsize, fee, entry_time)
    });
    #[cfg(not(feature = "usdt"))]
    drop(prepare);
}

/// Emits `net:inbound_message` while a consumer is attached.
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

/// Emits `net:outbound_message` while a consumer is attached.
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
