#![doc = include_str!("../README.md")]
#![forbid(unsafe_op_in_unsafe_fn)]

/// Native block type and block-level hashing helpers.
pub mod block;
/// Chain-level policy constants shared across tiers.
pub mod chain_constants;
/// Native consensus encoding and decoding for protocol types.
pub mod encode;
/// Fixed-width 256-bit hash type.
pub mod hash;
/// Native block header type and header hash computation.
pub mod header;
/// Transaction, witness-transaction, and block identifier newtypes.
pub mod ids;
/// Checked borrowed wire layout for blocks and transactions.
pub mod layout;
/// Bitcoin network constants.
pub mod network;
/// Fixed-layout transaction outpoint.
pub mod outpoint;
/// Native script and witness byte stacks.
pub mod script;
/// Native signature-hash computation for legacy, segwit v0, and taproot.
pub mod sighash;
/// Native transaction types and txid/wtxid computation.
pub mod tx;
/// Native protocol scalar newtypes: amount, sequence, locktime, compact target.
pub mod units;
/// Bitcoin compact-size integer codec.
pub mod varint;
/// Workspace release version constants for wire/RPC user-agent strings.
pub mod version;

pub use block::{Block, BlockBodyMetadata};
pub use encode::{
    ConsensusDecode, ConsensusEncode, DecodeError, Sink, consensus_bytes, deserialize,
};
pub use hash::{Hash256, HashError};
pub use header::Header;
pub use ids::{BlockHash, Txid, Wtxid};
pub use network::{ChainTxData, HeadersSyncParams, Network};
pub use outpoint::OutPoint;
pub use script::{Script, Witness};
pub use sighash::{
    AnnexError, CODESEPARATOR_POSITION, Sighash, SighashCache, SighashError, tapleaf_hash,
};
pub use tx::{Tx, TxIn, TxOut};
pub use units::{Amount, CompactTarget, LockTime, Sequence};
pub use version::{PKG_VERSION, USER_AGENT, client_version};

/// Wall-clock seconds since the Unix epoch, `0` when the clock predates it.
///
/// Shared wall-clock read for latency and rate-bucket bookkeeping. Consensus
/// timestamps come from block headers, never from this.
#[must_use]
pub fn unix_time_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

/// `u64` to `f64` without a silent `as` cast, which the workspace forbids.
///
/// Exact for every input up to `2^53`; above that the low half rounds, which is
/// inherent to `f64` and is what Bitcoin Core accepts for its estimates too.
#[must_use]
pub fn u64_to_f64(value: u64) -> f64 {
    const TWO_POW_32: f64 = 4_294_967_296.0;

    let high = u32::try_from(value >> 32).unwrap_or(u32::MAX);
    let low = u32::try_from(value & 0xffff_ffff).unwrap_or(u32::MAX);
    f64::from(high).mul_add(TWO_POW_32, f64::from(low))
}

/// [`u64_to_f64`] with a sign, for elapsed times that can run either way.
#[must_use]
pub fn i64_to_f64(value: i64) -> f64 {
    let magnitude = u64_to_f64(value.unsigned_abs());
    if value < 0 { -magnitude } else { magnitude }
}

#[cfg(test)]
mod float_conversion_tests {
    use super::{i64_to_f64, u64_to_f64};

    #[test]
    // suboptimal_flops fires on 1.99 clippy but not 1.97 — toolchain-dependent
    // suppression, so expect's self-audit can't be used here.
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
            // Independently derived: the halves recombined by hand.
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
