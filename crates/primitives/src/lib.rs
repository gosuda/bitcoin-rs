#![doc = include_str!("../README.md")]
#![forbid(unsafe_op_in_unsafe_fn)]

pub mod block;
pub mod chain_constants {
    /// Minimum number of blocks kept below the active tip for Core-compatible
    /// reorg safety.
    pub const CORE_REORG_SAFETY_MARGIN: u32 = 288;
}

pub mod encode;
pub mod endpoint;
pub use endpoint::{EndpointHost, NetworkLabel, PeerAddress, PeerEndpoint, PeerNetwork};
pub mod hash;
pub mod header;
pub mod ids;
pub mod layout;
pub mod network;
pub mod outpoint;
pub mod script;
pub mod sighash;
pub mod tx;
pub mod units;
pub mod varint;
pub mod version;

pub use block::{Block, BlockBodyMetadata, BlockPayload};
pub use encode::{
    ConsensusDecode, ConsensusEncode, DecodeError, Sink, consensus_bytes, deserialize,
};
pub use hash::{Hash256, HashError};
pub use header::Header;
pub use ids::{BlockHash, Txid, Wtxid};
pub use network::{AssumeUtxoData, ChainTxData, HeadersSyncParams, Network};
pub use outpoint::OutPoint;
pub use script::{Script, Witness};
pub use sighash::{
    AnnexError, CODESEPARATOR_POSITION, Sighash, SighashCache, SighashError, tapleaf_hash,
};
pub use tx::{Tx, TxIn, TxOut};
pub use units::{Amount, CompactTarget, LockTime, Sequence};
pub use version::{PKG_VERSION, USER_AGENT, client_version};

/// Wall-clock seconds since the Unix epoch, `0` when the clock predates it.
#[must_use]
pub fn unix_time_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

#[must_use]
pub fn u64_to_f64(value: u64) -> f64 {
    const TWO_POW_32: f64 = 4_294_967_296.0;

    let high = u32::try_from(value >> 32).unwrap_or(u32::MAX);
    let low = u32::try_from(value & 0xffff_ffff).unwrap_or(u32::MAX);
    f64::from(high).mul_add(TWO_POW_32, f64::from(low))
}

#[must_use]
pub fn i64_to_f64(value: i64) -> f64 {
    let magnitude = u64_to_f64(value.unsigned_abs());
    if value < 0 { -magnitude } else { magnitude }
}

#[cfg(test)]
mod float_conversion_tests {
    use super::{i64_to_f64, u64_to_f64};

    #[test]
    #[allow(clippy::suboptimal_flops)]
    fn u64_to_f64_is_exact_below_two_to_the_fifty_third() {
        for value in [
            0_u64,
            1,
            4_294_967_295,
            4_294_967_296,
            1_315_805_869,
            1 << 52,
        ] {
            let expected = f64::from(u32::try_from(value >> 32).unwrap_or(u32::MAX))
                * 4_294_967_296.0_f64
                + f64::from(u32::try_from(value & 0xffff_ffff).unwrap_or(u32::MAX));
            assert!(
                (u64_to_f64(value) - expected).abs() < f64::EPSILON,
                "{value}"
            );
        }
    }

    #[test]
    fn i64_to_f64_carries_the_sign() {
        assert!((i64_to_f64(-3_600) + 3_600.0).abs() < f64::EPSILON);
        assert!((i64_to_f64(3_600) - 3_600.0).abs() < f64::EPSILON);
        assert!((i64_to_f64(0) - 0.0).abs() < f64::EPSILON);
    }
}
