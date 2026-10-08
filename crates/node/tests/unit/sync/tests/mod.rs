use std::sync::Arc;

use arc_swap::ArcSwapOption;
use bitcoin_rs_chain::{BlockTree, NodeStatus, TipSnapshot, regtest_fixture};
use bitcoin_rs_primitives::{
    Block, BlockHash, Hash256, Header, Network, OutPoint, Tx, TxIn, TxOut, Txid, consensus_bytes,
};
use bitcoin_rs_script::push_int;
use bitcoin_rs_utxo::UtxoSet;
use hashbrown::HashMap;
use parking_lot::RwLock;

use bitcoin_rs_chainstate::Chainstate;
use bitcoin_rs_p2p::sync::chain::{SyncChain, WindowApplyDisposition};

#[test]
fn window_failure_keeps_committed_followers_and_native_retry_policy()
-> Result<(), Box<dyn std::error::Error>> {
    let genesis = Network::Regtest.genesis_block();
    let first = regtest_fixture::mined_block_with_prev_hash(
        genesis.block_hash(),
        1,
        vec![regtest_fixture::coinbase(1)],
    )?;
    let invalid = regtest_fixture::mined_block_with_prev_hash(
        first.block_hash(),
        2,
        vec![regtest_fixture::coinbase(2), regtest_fixture::coinbase(3)],
    )?;
    let child = regtest_fixture::mined_block_with_prev_hash(
        invalid.block_hash(),
        3,
        vec![regtest_fixture::coinbase(3)],
    )?;
    let invalid_hashes = vec![
        Hash256::from(invalid.block_hash()),
        Hash256::from(child.block_hash()),
    ];
    let mut tree = BlockTree::new();
    let mut parent = tree.insert_node(None, genesis.header, NodeStatus::HeaderValid)?;
    for block in [&first, &invalid, &child] {
        parent = tree.insert_node(Some(parent), block.header, NodeStatus::HeaderValid)?;
    }
    let handles = Arc::new(apply_handles(
        tree.tip_handle(),
        Arc::new(ArcSwapOption::empty()),
        Arc::new(RwLock::new(tree)),
    ));
    let followers = crate::chain_effects::ChainFollowers::noop();
    let adapter = super::NodeSyncChain {
        block_tree: handles.block_tree_reader(),
        handles: Arc::clone(&handles),
        followers: followers.clone(),
        assumeutxo: None,
    };
    adapter.bootstrap_genesis();
    let mut mutated = invalid.clone();
    mutated.txs.pop();
    for (blocks, disposition, applied, invalidated) in [
        (
            vec![&first, &mutated, &child],
            WindowApplyDisposition::BodyMutated,
            1,
            vec![],
        ),
        (
            vec![&invalid, &child],
            WindowApplyDisposition::Permanent,
            0,
            invalid_hashes,
        ),
    ] {
        let bodies = blocks
            .iter()
            .map(|&block| bytes::Bytes::from(consensus_bytes(block)))
            .collect::<Vec<_>>();
        let error = match adapter.commit_window(&blocks, &bodies) {
            Ok(count) => panic!("invalid window committed {count} blocks"),
            Err(error) => error,
        };
        assert_eq!(error.disposition, disposition);
        assert_eq!(error.applied, applied);
        assert_eq!(error.invalidated.as_ref(), invalidated);
        let tip = adapter.applied_tip().ok_or("committed tip missing")?;
        assert_eq!(
            (tip.height, tip.hash),
            (1, Hash256::from(first.block_hash()))
        );
        let log = followers.block_log();
        let log = log.read();
        assert_eq!(log.len(), 2);
        assert_eq!(
            log.last().ok_or("committed follower missing")?.hash,
            first.block_hash()
        );
    }
    Ok(())
}

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
    if let Err(error) = regtest_fixture::mine_block_to_declared_target(&mut block) {
        panic!("regtest target must be reachable: {error}");
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
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                outputs: vec![TxOut {
                    value: Amount::from_sat(subsidy - 100_000),
                    script_pubkey: Script::new(),
                }],
                lock_time: LockTime::ZERO,
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
