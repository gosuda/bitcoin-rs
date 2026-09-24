use std::sync::Arc;

use arc_swap::ArcSwapOption;
use bitcoin_rs_chain::{BlockTree, NodeStatus, TipSnapshot, compact_is_met_by, regtest_fixture};
use bitcoin_rs_primitives::{
    Block, BlockHash, Hash256, Header, Network, OutPoint, Tx, TxIn, TxOut, Txid, consensus_bytes,
};
use bitcoin_rs_script::push_int;
use bitcoin_rs_utxo::UtxoSet;
use hashbrown::HashMap;
use parking_lot::RwLock;

use bitcoin_rs_chainstate::Chainstate;

#[allow(clippy::arc_with_non_send_sync)]
fn apply_handles(
    chain_tip: Arc<ArcSwapOption<TipSnapshot>>,
    applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
    block_tree: Arc<RwLock<BlockTree>>,
) -> Chainstate {
    Chainstate::new(
        Network::Regtest,
        chain_tip,
        applied_tip,
        block_tree,
        Arc::new(UtxoSet::new()),
        Arc::new(bitcoin_rs_utxo::stats::CoinStatsListener::new(
            bitcoin_rs_utxo::stats::CoinStats::default(),
        )),
        Arc::new(bitcoin_rs_chainstate::events::ChainEventPublisher::detached(0)),
    )
}

const GENESIS_TIME: u32 = 1_296_688_602;

fn mined_block_with_prev_hash(prev_blockhash: BlockHash, height: u32, txdata: Vec<Tx>) -> Block {
    use bitcoin_rs_primitives::CompactTarget;
    let mut block = Block {
        header: Header {
            version: 1,
            prev_blockhash,
            merkle_root: Hash256::default(),
            time: GENESIS_TIME.saturating_add(height),
            bits: CompactTarget::from_consensus(regtest_fixture::REGTEST_BITS),
            nonce: 0,
        },
        txs: txdata,
    };
    block.header.merkle_root = regtest_fixture::merkle_root(&block.txs).unwrap_or_default();
    while !compact_is_met_by(block.header.bits, block.block_hash().into()) {
        block.header.nonce = block.header.nonce.saturating_add(1);
    }
    block
}

type MaturedChain = (
    Chainstate,
    Vec<Block>,
    HashMap<Hash256, (Block, bytes::Bytes)>,
);

fn matured_chain(depth: u32) -> Result<MaturedChain, Box<dyn std::error::Error>> {
    use bitcoin_rs_primitives::{Amount, LockTime, Script, Sequence, Witness};
    let genesis = Network::Regtest.genesis_block();
    let mut tree = BlockTree::new();
    let mut parent = tree.insert_node(None, genesis.header, NodeStatus::HeaderValid)?;
    let subsidy = 5_000_000_000_u64;
    let mut prev_hash = genesis.block_hash();
    let mut blocks: Vec<Block> = Vec::new();
    for height in 1..=depth {
        let mut coinbase = regtest_fixture::coinbase(height);
        if height == 1 {
            coinbase.outputs[0].value = Amount::from_sat(subsidy);
        }
        let mut txs = vec![coinbase];
        if height == depth {
            let first_txid = blocks[0].txs[0].txid();
            txs.push(Tx {
                version: 2,
                inputs: vec![TxIn {
                    previous_output: OutPoint::new(first_txid, 0),
                    script_sig: Script::from_bytes(push_int(1)),
                    sequence: Sequence::from_consensus(0xffff_ffff),
                    witness: Witness::new(),
                }],
                outputs: vec![TxOut {
                    value: Amount::from_sat(subsidy - 100_000),
                    script_pubkey: Script::new(),
                }],
                lock_time: LockTime::from_consensus(0),
            });
        }
        let block = mined_block_with_prev_hash(prev_hash, height, txs);
        parent = tree.insert_node(Some(parent), block.header, NodeStatus::HeaderValid)?;
        prev_hash = block.block_hash();
        blocks.push(block);
    }
    let handles = apply_handles(
        tree.tip_handle(),
        Arc::new(ArcSwapOption::empty()),
        Arc::new(RwLock::new(tree)),
    );
    handles.apply_block(&genesis, None)?;
    for block in &blocks {
        handles.apply_block(block, None)?;
    }
    let bodies = blocks
        .iter()
        .map(|block| {
            (
                Hash256::from_le_bytes(block.block_hash().as_bytes()),
                (block.clone(), bytes::Bytes::from(consensus_bytes(block))),
            )
        })
        .collect();
    Ok((handles, blocks, bodies))
}

#[cfg(test)]
mod transitions_2;

#[cfg(test)]
mod transitions_3;

#[cfg(test)]
mod transitions_7;
