use std::sync::Arc;

use arc_swap::ArcSwapOption;
use bitcoin_rs_consensus::primitives::{
    Block, BlockHash, BlockImage, Hash256, Header, Network, OutPoint, Tx, TxIn, TxOut, Txid,
};
use bitcoin_rs_consensus::script::push_int;
use bitcoin_rs_execution::chain::{BlockTree, NodeStatus, TipSnapshot, regtest_fixture};
use bitcoin_rs_storage::utxo::UtxoSet;
use hashbrown::HashMap;
use parking_lot::RwLock;

use crate::p2p::sync::chain::{SyncChain, WindowApplyDisposition};
use crate::test_support::TestError;
use bitcoin_rs_execution::Chainstate;

#[test]
fn window_failure_keeps_committed_followers_and_native_retry_policy()
-> Result<(), crate::test_support::TestError> {
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
        budget: Arc::new(crate::budget::NodeBudget::from_dbcache_bytes(16, 1)),
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
        let owned_payloads = blocks
            .iter()
            .map(|block| BlockImage::from_local((*block).clone()))
            .collect::<Vec<_>>();
        let payloads: Vec<&BlockImage> = owned_payloads.iter().collect();
        let error = match adapter.commit_window(&payloads) {
            Ok(count) => panic!("invalid window committed {count} blocks"),
            Err(error) => error,
        };
        assert_eq!(error.disposition, disposition);
        assert_eq!(error.applied, applied);
        assert_eq!(error.invalidated.as_ref(), invalidated);
        let tip = adapter
            .applied_tip()
            .ok_or(TestError::Missing("committed tip"))?;
        assert_eq!(
            (tip.height, tip.hash),
            (1, Hash256::from(first.block_hash()))
        );
        let log = followers.block_log();
        let log = log.read();
        assert_eq!(log.len(), 2);
        assert_eq!(
            log.last()
                .ok_or(TestError::Missing("committed follower"))?
                .hash,
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
        Arc::new(bitcoin_rs_storage::utxo::stats::CoinStatsListener::new(
            bitcoin_rs_storage::utxo::stats::CoinStats::default(),
        )),
        Arc::new(bitcoin_rs_execution::events::ChainEventPublisher::detached(
            0,
        )),
    )
}

const GENESIS_TIME: u32 = 1_296_688_602;

fn mined_block_with_prev_hash(prev_blockhash: BlockHash, height: u32, txdata: Vec<Tx>) -> Block {
    use bitcoin_rs_consensus::primitives::CompactTarget;
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

type MaturedChain = (Chainstate, Vec<Block>, HashMap<Hash256, BlockImage>);

fn matured_chain(depth: u32) -> Result<MaturedChain, crate::test_support::TestError> {
    use bitcoin_rs_consensus::primitives::{Amount, LockTime, Script, Sequence, Witness};
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
    handles.apply_block(&BlockImage::from_local(genesis))?;
    for block in &blocks {
        handles.apply_block(&BlockImage::from_local(block.clone()))?;
    }
    let bodies = blocks
        .iter()
        .map(|block| {
            (
                Hash256::from_le_bytes(block.block_hash().as_bytes()),
                BlockImage::from_local(block.clone()),
            )
        })
        .collect();
    Ok((handles, blocks, bodies))
}

#[cfg(test)]
mod staged_branch_switch;

#[cfg(test)]
mod reorg_invalidation;

#[cfg(test)]
mod branch_connect_mempool;

#[cfg(test)]
mod fatal_halt;

// BUD-04
#[test]
fn historical_validation_runs_under_a_background_cpu_permit() {
    let budget = crate::budget::NodeBudget::from_dbcache_bytes(16, 4);
    let cpu = budget.cpu();
    let observed = super::with_historical_background_permit(&budget, || cpu.background_in_flight());
    assert_eq!(
        observed, 1,
        "historical validation must hold one background CPU permit"
    );
    assert_eq!(
        cpu.background_in_flight(),
        0,
        "the permit releases on return"
    );
}
// SYNC-04
#[test]
fn fatal_window_settlement_closes_the_chain_for_recovery() -> Result<(), TestError> {
    use bitcoin_rs_consensus::ValidationEngine;
    use bitcoin_rs_execution::{ApplyError, WindowApplyDisposition, WindowApplyError};
    use bitcoin_rs_mempool::{Mempool, MempoolGateway, MempoolLimits};

    let genesis = Network::Regtest.genesis_block();
    let mut tree = BlockTree::new();
    tree.insert_node(None, genesis.header, NodeStatus::HeaderValid)?;
    let handles = apply_handles(
        tree.tip_handle(),
        Arc::new(ArcSwapOption::empty()),
        Arc::new(RwLock::new(tree)),
    );
    let gateway = Arc::new(MempoolGateway::new(
        Arc::new(RwLock::new(Mempool::new(MempoolLimits::default()))),
        None,
        ValidationEngine::Native,
        None,
    ));
    let followers = crate::chain_effects::ChainFollowers::new(
        Arc::new(RwLock::new(
            bitcoin_rs_projection::block_log::BlockLog::new(),
        )),
        Arc::new(crate::NoOpZmqPublisher),
        None,
        None,
        Arc::new(crate::mining::MiningGenerationSignal::new()),
        Some(gateway),
    );
    let transition = handles
        .begin_transition()
        .map_err(|error| TestError::Apply(Box::new(error)))?;
    let change = followers
        .begin_mempool_change()
        .map_err(|error| TestError::Apply(Box::new(error)))?;
    let fatal = WindowApplyError {
        applied: 0,
        committed: Vec::new(),
        source: Box::new(ApplyError::CoinStoreRead(
            bitcoin_rs_storage::StorageError::InvalidOperation("fatal settlement probe"),
        )),
        disposition: WindowApplyDisposition::Fatal,
        invalidated: Box::default(),
    };
    let settled = super::settle_window_failure(transition, change, fatal);
    assert_eq!(settled.disposition, WindowApplyDisposition::Fatal);
    assert!(
        handles.is_closed_for_recovery(),
        "a fatal window failure must close the chain for recovery"
    );
    assert!(
        matches!(handles.begin_transition(), Err(ApplyError::Shutdown)),
        "a closed chain must refuse the next transition instead of retrying"
    );
    Ok(())
}
