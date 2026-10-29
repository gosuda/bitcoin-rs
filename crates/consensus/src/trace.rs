//! Bitcoin Core-compatible USDT probes declared in `probes.d`.

#![allow(
    clippy::items_after_statements,
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

mod generated {
    #[cfg(feature = "usdt")]
    usdt::dtrace_provider!("probes.d");
}

#[cfg(feature = "usdt")]
fn address_of(buffer: *const u8) -> u64 {
    u64::try_from(buffer.addr()).unwrap_or(0)
}

pub type MessageArgs = (i64, String, String, String, u64, *const u8);

pub fn block_connected(prepare: impl FnOnce() -> (*const u8, i32, u64, i32, i64, i64)) {
    #[cfg(feature = "usdt")]
    generated::validation::block_connected!(|| {
        let (hash, height, txs, inputs, sigops, elapsed_ns) = prepare();
        (address_of(hash), height, txs, inputs, sigops, elapsed_ns)
    });
    #[cfg(not(feature = "usdt"))]
    drop(prepare);
}

pub fn added(prepare: impl FnOnce() -> (*const u8, i32, i64)) {
    #[cfg(feature = "usdt")]
    generated::mempool::added!(|| {
        let (txid, vsize, fee) = prepare();
        (address_of(txid), vsize, fee)
    });
    #[cfg(not(feature = "usdt"))]
    drop(prepare);
}

pub fn removed(prepare: impl FnOnce() -> (*const u8, &'static str, i32, i64, u64)) {
    #[cfg(feature = "usdt")]
    generated::mempool::removed!(|| {
        let (txid, reason, vsize, fee, entry_time) = prepare();
        (address_of(txid), reason, vsize, fee, entry_time)
    });
    #[cfg(not(feature = "usdt"))]
    drop(prepare);
}

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

pub fn register_probes() {
    #[cfg(feature = "usdt")]
    {
        if let Err(error) = usdt::register_probes() {
            tracing::warn!(%error, "usdt probe registration failed; tracepoints may not be visible");
        }
    }
}
