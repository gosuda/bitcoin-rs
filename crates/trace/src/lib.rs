//! Optional Bitcoin Core-compatible USDT tracepoints.
//!
//! Every function in this crate is a no-op unless the consuming binary is
//! built with this crate's `usdt` feature enabled. When it is, the probes
//! carry Bitcoin Core's provider names (`validation`, `mempool`, `net`),
//! probe names, and argument layout — see [`probe_abi`] and `docs/tracing.md`
//! for the compatibility table.
//!
//! Hot-path semantics mirror Bitcoin Core's `src/util/trace.h`: each emission
//! site passes a `prepare` closure that *materialises* the probe arguments,
//! and the closure is only invoked when a consumer (bpftrace, BCC, `DTrace`,
//! …) has raised the probe's semaphore. With the feature on and nothing
//! attached the cost is one volatile semaphore load per probe site; with the
//! feature off every call is an empty function body and the closure is
//! dropped without running.

/// Documented argument ABI of every probe this crate defines.
pub mod probe_abi;

mod raw {
    // The usdt generator's probe macros cast their arguments to usize and
    // define an inline type-check item inside their expansion; that output
    // is not ours to reshape, so allow its lint set at this module.
    #![allow(
        clippy::items_after_statements,
        clippy::as_conversions,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    // Raw generated probe macros, one generated module per provider. The
    // generator names a module after each provider, so this private module
    // keeps the generated `validation`/`mempool`/`net` modules out of the
    // crate root where the public wrappers live. The provider definition
    // lives at the package root next to `Cargo.toml`, where the `usdt`
    // macro resolves it.
    #[cfg(feature = "usdt")]
    usdt::dtrace_provider!("probes.d");

    /// Buffer address for the emitter's by-value pointer arguments.
    ///
    /// Core passes hash and message buffers as pointers by value; see
    /// [`crate::probe_abi`] for why these travel as `u64`.
    #[cfg(feature = "usdt")]
    fn address_of(buffer: *const u8) -> u64 {
        u64::try_from(buffer.addr()).unwrap_or(0)
    }

    /// Fires `validation:block_connected` with prepared arguments.
    #[cfg(feature = "usdt")]
    pub(super) fn block_connected(prepare: impl FnOnce() -> super::BlockConnectedArgs) {
        validation::block_connected!(|| {
            let (hash, height, txs, inputs, sigops, elapsed_ns) = prepare();
            (address_of(hash), height, txs, inputs, sigops, elapsed_ns)
        });
    }

    /// Fires `mempool:added` with prepared arguments.
    #[cfg(feature = "usdt")]
    pub(super) fn added(prepare: impl FnOnce() -> super::AddedArgs) {
        mempool::added!(|| {
            let (txid, vsize, fee) = prepare();
            (address_of(txid), vsize, fee)
        });
    }

    /// Fires `mempool:removed` with prepared arguments.
    #[cfg(feature = "usdt")]
    pub(super) fn removed(prepare: impl FnOnce() -> super::RemovedArgs) {
        mempool::removed!(|| {
            let (txid, reason, vsize, fee, entry_time) = prepare();
            (address_of(txid), reason, vsize, fee, entry_time)
        });
    }

    /// Fires `net:inbound_message` with prepared arguments.
    #[cfg(feature = "usdt")]
    pub(super) fn inbound_message(prepare: impl FnOnce() -> super::MessageArgs) {
        net::inbound_message!(|| {
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
    }

    /// Fires `net:outbound_message` with prepared arguments.
    #[cfg(feature = "usdt")]
    pub(super) fn outbound_message(prepare: impl FnOnce() -> super::MessageArgs) {
        net::outbound_message!(|| {
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
    }
}

/// Prepared arguments of `validation:block_connected`.
///
/// `(block_hash, height, transactions, inputs, sigops_cost, elapsed_ns)`.
/// `block_hash` must address 32 bytes that outlive the probe call; callers
/// pass the hash's own byte array.
pub type BlockConnectedArgs = (*const u8, i32, u64, i32, i64, i64);

/// Prepared arguments of `mempool:added`.
///
/// `(txid, vsize, fee)`. `txid` must address 32 bytes that outlive the probe
/// call; callers pass the hash's own byte array.
pub type AddedArgs = (*const u8, i32, i64);

/// Prepared arguments of `mempool:removed`.
///
/// `(txid, reason, vsize, fee, entry_time)`. `txid` must address 32 bytes
/// that outlive the probe call.
pub type RemovedArgs = (*const u8, &'static str, i32, i64, u64);

/// Prepared arguments of `net:inbound_message` / `net:outbound_message`.
///
/// `(node_id, addr, conn_type, msg_type, payload_size, payload)`. `payload`
/// must address `payload_size` bytes that outlive the probe call; callers
/// pass the encoded frame's own byte slice.
pub type MessageArgs = (i64, String, String, String, u64, *const u8);

/// Fires `validation:block_connected` if probes are compiled in.
///
/// Arguments follow Bitcoin Core's `validation:block_connected` ABI; see
/// [`probe_abi::BLOCK_CONNECTED`]. `prepare` runs only while a consumer is
/// attached.
pub fn block_connected(prepare: impl FnOnce() -> BlockConnectedArgs) {
    #[cfg(feature = "usdt")]
    raw::block_connected(prepare);
    #[cfg(not(feature = "usdt"))]
    drop(prepare);
}

/// Fires `mempool:added` if probes are compiled in.
///
/// `prepare` runs only while a consumer is attached.
pub fn added(prepare: impl FnOnce() -> AddedArgs) {
    #[cfg(feature = "usdt")]
    raw::added(prepare);
    #[cfg(not(feature = "usdt"))]
    drop(prepare);
}

/// Fires `mempool:removed` if probes are compiled in.
///
/// `prepare` runs only while a consumer is attached.
pub fn removed(prepare: impl FnOnce() -> RemovedArgs) {
    #[cfg(feature = "usdt")]
    raw::removed(prepare);
    #[cfg(not(feature = "usdt"))]
    drop(prepare);
}

/// Fires `net:inbound_message` if probes are compiled in.
///
/// `prepare` runs only while a consumer is attached.
pub fn inbound_message(prepare: impl FnOnce() -> MessageArgs) {
    #[cfg(feature = "usdt")]
    raw::inbound_message(prepare);
    #[cfg(not(feature = "usdt"))]
    drop(prepare);
}

/// Fires `net:outbound_message` if probes are compiled in.
///
/// `prepare` runs only while a consumer is attached.
pub fn outbound_message(prepare: impl FnOnce() -> MessageArgs) {
    #[cfg(feature = "usdt")]
    raw::outbound_message(prepare);
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
