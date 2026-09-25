//! Window invalidation must keep the published header tip and the
//! assume-valid gate in sync with the mutated tree, exactly as reorg
//! invalidation does.

use std::sync::Arc;

use bitcoin_rs_chain::{NodeStatus, compact_is_met_by};
use bitcoin_rs_primitives::{
    Block, BlockHash, CompactTarget, Hash256, Header, Network, consensus_bytes,
};
use bitcoin_rs_utxo::UtxoSet;

use super::persistence_tests::{handles, seed_genesis};
use super::{ApplyError, AssumeValidGate, Chainstate, WindowApplyDisposition};

/// A solved, empty block: the commit refuses its body with `EmptyBlock`, a
/// permanent failure, while its header is already in the tree.
fn empty_child(prev_blockhash: BlockHash, height: u32) -> Result<Block, &'static str> {
    let mut block = Block {
        header: Header {
            version: 1,
            prev_blockhash,
            merkle_root: Hash256::default(),
            time: 1_296_688_602_u32.saturating_add(height),
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        },
        txs: Vec::new(),
    };
    while !compact_is_met_by(block.header.bits, block.header.compute_hash().0) {
        block.header.nonce = block
            .header
            .nonce
            .checked_add(1)
            .ok_or("test nonce exhausted")?;
    }
    Ok(block)
}

#[test]
fn window_invalidation_reevaluates_assume_valid() -> Result<(), Box<dyn std::error::Error>> {
    let genesis = Network::Regtest.genesis_block();
    let mut handles: Chainstate = handles(Network::Regtest, Arc::new(UtxoSet::new()));
    seed_genesis(&handles).map_err(|error: ApplyError| error.to_string())?;

    // The empty child at height 1 becomes both the assume-valid anchor and
    // the published header tip, so the gate starts trusted.
    let anchor = empty_child(genesis.block_hash(), 1)?;
    let anchor_hash = Hash256::from(anchor.block_hash());
    handles
        .block_tree
        .write()
        .insert_header(anchor.header, NodeStatus::HeaderValid)?;
    handles.assume_valid_gate = Arc::new(AssumeValidGate::with_anchor(Some((1, anchor_hash))));
    handles
        .assume_valid_gate
        .evaluate(&handles.block_tree.read());
    assert!(
        handles.assume_valid_gate.trusted(),
        "the anchor on the active header chain must start trusted"
    );

    let outcome = handles.apply_window(&[&anchor], &[bytes::Bytes::from(consensus_bytes(&anchor))]);
    let error = outcome.err().ok_or("an empty block must not commit")?;
    assert_eq!(error.disposition, WindowApplyDisposition::Permanent);
    assert_eq!(error.invalidated.to_vec(), vec![anchor_hash]);

    // The invalidation removed the anchor from the active chain. The shared
    // operation must have republished the best valid tip and re-evaluated
    // the gate against the mutated tree under the same write lock.
    assert!(
        !handles.assume_valid_gate.trusted(),
        "window invalidation must re-evaluate the assume-valid gate"
    );
    let tip = handles
        .chain_tip()
        .load_full()
        .ok_or("window invalidation must republish the best valid tip")?;
    assert_eq!(tip.hash, Hash256::from(genesis.block_hash()));
    Ok(())
}
