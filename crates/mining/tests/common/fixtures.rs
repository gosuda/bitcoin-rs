#![allow(
    dead_code,
    reason = "each integration test binary uses a subset of the shared fixtures"
)]

use std::error::Error;

use bitcoin_rs_mining::CandidateContext;
use bitcoin_rs_primitives::{CompactTarget, Hash256, Network, Tx, encode::consensus_bytes};

pub(crate) fn p2pkh() -> Vec<u8> {
    [vec![0x76, 0xa9, 0x14], vec![0x11; 20], vec![0x88, 0xac]].concat()
}

/// Regtest context; callers override only the facts their scenario varies.
pub(crate) fn context(segwit_active: bool, max_sigops: u64) -> CandidateContext {
    CandidateContext {
        previous_block_hash: Hash256::from_le_bytes(&[0x11; 32]),
        height: 100,
        version: 0x2000_0000,
        bits: CompactTarget::from_consensus(0x207f_ffff),
        min_time: 1,
        current_time: 2,
        locktime_cutoff: 1,
        network: Network::Regtest,
        csv_active: true,
        segwit_active,
        max_weight: 4_000_000,
        max_size: 4_000_000,
        max_sigops,
    }
}

pub(crate) fn oracle_transaction(tx: &Tx) -> Result<bitcoin::Transaction, Box<dyn Error>> {
    Ok(bitcoin::consensus::deserialize(&consensus_bytes(tx))?)
}
