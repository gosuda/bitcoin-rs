use bitcoin::hashes::Hash as _;
use bitcoin_rs_primitives::{BlockHash, CompactTarget};

/// Checks that the header hash satisfies the compact target, using bitcoin's
/// compact-target decode and comparison.
///
/// Deliberately dependent on the `bitcoin` crate, not native consensus code,
/// so a differential verdict compares two implementations rather than the
/// same logic against itself.
pub(crate) fn pow_is_met(bits: CompactTarget, hash: &BlockHash) -> bool {
    let target = bitcoin::pow::Target::from_compact(bitcoin::pow::CompactTarget::from_consensus(
        bits.to_consensus(),
    ));
    target.is_met_by(bitcoin::BlockHash::from_byte_array(*hash.as_bytes()))
}
