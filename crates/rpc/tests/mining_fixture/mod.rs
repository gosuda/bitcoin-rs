//! Shared canned mining fixtures for the rpc integration tests.
//!
//! `compat_template`/`smoke_template` and `compat_info`/`smoke_info` were
//! byte-identical literals duplicated across test binaries; both now read the
//! same fixture, parameterized on the only differing fields.

extern crate alloc;

use alloc::sync::Arc;

use bitcoin_rs_mining::{
    BlockTemplate, Candidate, MiningCapability, MiningInfo, TemplateId, TemplateMutation,
};
use bitcoin_rs_primitives::{
    CompactTarget, Hash256, LockTime, Network, OutPoint, Script, Sequence, Tx, TxIn, Txid, Witness,
};

/// Canned template; callers pin `capabilities` and `mutable` to the contract
/// their test exercises.
pub(crate) fn canned_template(
    capabilities: Vec<MiningCapability>,
    mutable: Vec<TemplateMutation>,
) -> BlockTemplate {
    let previous_block_hash = Hash256::default();
    BlockTemplate {
        candidate: Arc::new(Candidate {
            template_id: TemplateId::new(&previous_block_hash, 0),
            previous_block_hash,
            height: 0,
            version: 0x2000_0000,
            bits: CompactTarget::from_consensus(0x1d00_ffff),
            min_time: 0,
            current_time: 0,
            csv_active: false,
            segwit_active: false,
            max_weight: 4_000_000,
            max_size: 4_000_000,
            max_sigops: 80_000,
            mempool_sequence: 0,
            coinbase: Tx {
                version: 1,
                lock_time: LockTime::ZERO,
                inputs: vec![TxIn {
                    previous_output: OutPoint::new(Txid::default(), u32::MAX),
                    script_sig: Script::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                outputs: Vec::new(),
            },
            coinbase_value: 0,
            fees: 0,
            weight: 0,
            size: 0,
            sigop_cost: 0,
            transactions: Vec::new(),
            witness_merkle_root: None,
            witness_reserved_value: None,
            witness_commitment: None,
        }),
        rules: Vec::new(),
        version_bits_available: Vec::new(),
        version_bits_required: 0,
        capabilities,
        mutable,
        submit_old: None,
        signet: None,
        work_id: None,
    }
}

/// Canned mining info for the typed mining-response schema.
pub(crate) fn canned_info() -> MiningInfo {
    MiningInfo {
        blocks: 0,
        last_candidate: None,
        bits: CompactTarget::from_consensus(0x207f_ffff),
        difficulty: 1.0,
        network_hashes_per_second: 0.0,
        pooled_transactions: 0,
        network: Network::Regtest,
        next_bits: CompactTarget::from_consensus(0x207f_ffff),
        next_difficulty: 1.0,
        minimum_fee_rate: 1_000,
        signet: None,
        warnings: Vec::new(),
    }
}
