use bitcoin::hashes::Hash as _;
use bitcoin_rs_primitives::{BlockHash, CompactTarget};

pub(crate) fn pow_is_met(bits: CompactTarget, hash: &BlockHash) -> bool {
    let target = bitcoin::pow::Target::from_compact(bitcoin::pow::CompactTarget::from_consensus(
        bits.to_consensus(),
    ));
    target.is_met_by(bitcoin::BlockHash::from_byte_array(*hash.as_bytes()))
}
