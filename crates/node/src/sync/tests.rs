use std::sync::Arc;

use arc_swap::ArcSwapOption;
use bitcoin_rs_consensus::primitives::{
    Block, BlockHash, BlockImage, Hash256, Header, Network, OutPoint, Tx, TxIn, TxOut, Txid,
};
use bitcoin_rs_consensus::script::push_int;
use bitcoin_rs_execution::chain::{BlockTree, NodeStatus, TipSnapshot, regtest_fixture};
use bitcoin_rs_storage::{split_chainstate_cache_budget, utxo::UtxoSet};
use hashbrown::HashMap;
use parking_lot::{Mutex, RwLock};

use crate::p2p::sync::chain::{SyncChain, WindowApplyDisposition, WindowCommitError};
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
        budget: Arc::new(crate::budget::NodeBudget::from_chainstate_cache_budget(
            split_chainstate_cache_budget(16),
            1,
        )),
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

#[test]
fn with_historical_background_permit_holds_one_permit_during_closure() {
    let budget = crate::budget::NodeBudget::from_chainstate_cache_budget(
        split_chainstate_cache_budget(16),
        4,
    );
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
        disposition: WindowApplyDisposition::Operational,
        invalidated: Box::default(),
    };
    let settled = super::settle_window_failure(transition, change, fatal);
    assert_eq!(settled.disposition, WindowApplyDisposition::Fatal);
    assert!(
        handles.is_closed_for_recovery(),
        "a fatal window failure must close the chain for recovery"
    );
    assert!(
        handles.shutdown_reader().is_triggered(),
        "a fatal window failure must request node shutdown"
    );
    assert!(
        matches!(handles.begin_transition(), Err(ApplyError::Shutdown)),
        "a closed chain must refuse the next transition instead of retrying"
    );
    Ok(())
}

struct RefusedWindowObserver {
    gateway: Mutex<Option<Arc<bitcoin_rs_mempool::MempoolGateway>>>,
    adapter: Mutex<Option<Arc<super::NodeSyncChain>>>,
    payloads: Mutex<Vec<BlockImage>>,
    entered: Mutex<Option<crossbeam_channel::Sender<()>>>,
    release: Mutex<Option<crossbeam_channel::Receiver<()>>>,
    outcome: Mutex<Option<ObservedWindow>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ObservedWindow {
    Committed {
        applied: usize,
    },
    Refused {
        applied: usize,
        disposition: WindowApplyDisposition,
        invalidated: Vec<Hash256>,
    },
}

impl bitcoin_rs_mempool::MempoolObserver for RefusedWindowObserver {
    fn on_mutation(&self, envelope: &bitcoin_rs_mempool::MutationEnvelope) {
        if envelope.result.sequence_base != 1 {
            return;
        }
        let Some(entered) = self.entered.lock().take() else {
            return;
        };
        if entered.send(()).is_err() {
            return;
        }
        let Some(release) = self.release.lock().take() else {
            return;
        };
        if release.recv().is_err() {
            return;
        }
        let (Some(gateway), Some(adapter)) =
            (self.gateway.lock().clone(), self.adapter.lock().clone())
        else {
            return;
        };
        for index in 0..8u32 {
            if gateway
                .insert_entry(
                    bitcoin_rs_mempool::AdmissionOrigin::Rpc,
                    bitcoin_rs_mempool::MempoolEntry::new(
                        Arc::new(refusal_probe_tx(40, index)),
                        100,
                        1_000,
                        1,
                        0,
                        0,
                    ),
                )
                .is_err()
            {
                panic!("nested admission must fit under the delivery ceiling");
            }
        }
        let payloads = self.payloads.lock().clone();
        let window: Vec<&BlockImage> = payloads.iter().collect();
        let observed = match adapter.commit_window(&window) {
            Ok(applied) => ObservedWindow::Committed { applied },
            Err(WindowCommitError {
                applied,
                disposition,
                invalidated,
                ..
            }) => ObservedWindow::Refused {
                applied,
                disposition,
                invalidated: invalidated.to_vec(),
            },
        };
        *self.outcome.lock() = Some(observed);
    }
}

fn refusal_probe_tx(thread: u8, index: u32) -> Tx {
    use bitcoin_rs_consensus::primitives::{Amount, LockTime, Script, Sequence};

    let mut bytes = [thread; 32];
    bytes[0..4].copy_from_slice(&index.to_le_bytes());
    Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&bytes)), 0),
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: bitcoin_rs_consensus::primitives::Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: Script::from_bytes(vec![0x51, thread]),
        }],
    }
}

struct RefusalWindowFixture {
    handles: Arc<Chainstate>,
    gateway: Arc<bitcoin_rs_mempool::MempoolGateway>,
    followers: crate::chain_effects::ChainFollowers,
    adapter: Arc<super::NodeSyncChain>,
    observer: Arc<RefusedWindowObserver>,
    entered: crossbeam_channel::Receiver<()>,
    release: crossbeam_channel::Sender<()>,
}

fn refusal_window_fixture(payload_blocks: &[Block]) -> Result<RefusalWindowFixture, TestError> {
    use bitcoin_rs_consensus::ValidationEngine;
    use bitcoin_rs_mempool::{BodyInterest, Mempool, MempoolGateway, MempoolLimits};

    let (entered_tx, entered_rx) = crossbeam_channel::bounded::<()>(1);
    let (release_tx, release_rx) = crossbeam_channel::bounded::<()>(1);
    let observer = Arc::new(RefusedWindowObserver {
        gateway: Mutex::new(None),
        adapter: Mutex::new(None),
        payloads: Mutex::new(Vec::new()),
        entered: Mutex::new(Some(entered_tx)),
        release: Mutex::new(Some(release_rx)),
        outcome: Mutex::new(None),
    });
    let observer_handle: Arc<dyn bitcoin_rs_mempool::MempoolObserver> = observer.clone();
    let gateway = Arc::new(MempoolGateway::new(
        Arc::new(RwLock::new(Mempool::new(MempoolLimits::default()))),
        Some((observer_handle, BodyInterest::Metadata)),
        ValidationEngine::Native,
        None,
    ));
    *observer.gateway.lock() = Some(Arc::clone(&gateway));
    let followers = crate::chain_effects::ChainFollowers::new(
        Arc::new(RwLock::new(
            bitcoin_rs_projection::block_log::BlockLog::new(),
        )),
        Arc::new(crate::NoOpZmqPublisher),
        None,
        None,
        Arc::new(crate::mining::MiningGenerationSignal::new()),
        Some(Arc::clone(&gateway)),
    );
    let genesis = Network::Regtest.genesis_block();
    let mut tree = BlockTree::new();
    let mut parent = tree.insert_node(None, genesis.header, NodeStatus::HeaderValid)?;
    for block in payload_blocks {
        parent = tree.insert_node(Some(parent), block.header, NodeStatus::HeaderValid)?;
    }
    let handles = Arc::new(apply_handles(
        tree.tip_handle(),
        Arc::new(ArcSwapOption::empty()),
        Arc::new(RwLock::new(tree)),
    ));
    let adapter = Arc::new(super::NodeSyncChain {
        block_tree: handles.block_tree_reader(),
        handles: Arc::clone(&handles),
        followers: followers.clone(),
        assumeutxo: None,
        budget: Arc::new(crate::budget::NodeBudget::from_chainstate_cache_budget(
            split_chainstate_cache_budget(16),
            1,
        )),
    });
    adapter.bootstrap_genesis();
    assert!(
        handles.applied_tip_snapshot().is_some(),
        "genesis must bootstrap before the refusal probe runs"
    );
    assert!(
        gateway.stable_generation().is_some(),
        "bootstrap must settle the mempool fence before the probe floods it"
    );
    Ok(RefusalWindowFixture {
        handles,
        gateway,
        followers,
        adapter,
        observer,
        entered: entered_rx,
        release: release_tx,
    })
}

fn drive_refused_window(
    fixture: RefusalWindowFixture,
    payloads: Vec<BlockImage>,
) -> Result<(ObservedWindow, RefusalWindowFixture), TestError> {
    *fixture.observer.payloads.lock() = payloads;
    *fixture.observer.adapter.lock() = Some(Arc::clone(&fixture.adapter));
    let parked_gateway = Arc::clone(&fixture.gateway);
    let parked = std::thread::spawn(move || {
        parked_gateway.insert_entry(
            bitcoin_rs_mempool::AdmissionOrigin::Rpc,
            bitcoin_rs_mempool::MempoolEntry::new(
                Arc::new(refusal_probe_tx(200, 0)),
                100,
                1_000,
                1,
                0,
                0,
            ),
        )
    });
    fixture
        .entered
        .recv_timeout(std::time::Duration::from_secs(10))?;
    for index in 0..100u32 {
        fixture.gateway.insert_entry(
            bitcoin_rs_mempool::AdmissionOrigin::Rpc,
            bitcoin_rs_mempool::MempoolEntry::new(
                Arc::new(refusal_probe_tx(10, index)),
                100,
                1_000,
                1,
                0,
                0,
            ),
        )?;
    }
    assert_eq!(
        fixture.gateway.publish_len(),
        100,
        "the flood must park exactly at the delivery bound before release"
    );
    fixture
        .release
        .send(())
        .map_err(|error| TestError::message(error.to_string()))?;
    parked
        .join()
        .map_err(|_| TestError::ThreadPanicked)?
        .map_err(TestError::Mempool)?;
    let observed = fixture
        .observer
        .outcome
        .lock()
        .clone()
        .ok_or(TestError::Missing("window outcome"))?;
    Ok((observed, fixture))
}

fn assert_refused_window_state(
    fixture: &RefusalWindowFixture,
    genesis: &Block,
) -> Result<(), TestError> {
    assert!(
        fixture.handles.is_closed_for_recovery(),
        "a post-commit follower refusal must close the chain for recovery"
    );
    assert!(
        fixture.handles.shutdown_reader().is_triggered(),
        "a post-commit follower refusal must request node shutdown"
    );
    assert!(
        matches!(
            fixture.handles.begin_transition(),
            Err(bitcoin_rs_execution::ApplyError::Shutdown)
        ),
        "a halted chain must refuse the next transition instead of reopening"
    );
    assert!(
        fixture.gateway.stable_generation().is_none(),
        "a post-commit follower refusal must never finish the mempool generation"
    );
    let log = fixture.followers.block_log();
    let log = log.read();
    assert_eq!(
        log.len(),
        1,
        "the refused window must record no follower entries beyond genesis"
    );
    assert_eq!(
        log.last()
            .ok_or(TestError::Missing("genesis follower record"))?
            .hash,
        genesis.block_hash(),
        "the follower stream must stop at the bootstrapped genesis"
    );
    assert_eq!(
        fixture
            .followers
            .epoch()
            .current()
            .map(|epoch| epoch.tip.hash),
        Some(Hash256::from(genesis.block_hash())),
        "the refused window must not advance the follower epoch"
    );
    Ok(())
}

// SYNC-04, SYNC-06, MPL-04
#[test]
fn a_fully_committed_window_halts_when_a_follower_refuses_settlement() -> Result<(), TestError> {
    let genesis = Network::Regtest.genesis_block();
    let first =
        mined_block_with_prev_hash(genesis.block_hash(), 1, vec![regtest_fixture::coinbase(1)]);
    let second =
        mined_block_with_prev_hash(first.block_hash(), 2, vec![regtest_fixture::coinbase(2)]);
    let payloads = vec![
        BlockImage::from_local(first.clone()),
        BlockImage::from_local(second.clone()),
    ];
    let fixture = refusal_window_fixture(&[first.clone(), second.clone()])?;
    let (observed, fixture) = drive_refused_window(fixture, payloads)?;
    assert_eq!(
        observed,
        ObservedWindow::Refused {
            applied: 2,
            disposition: WindowApplyDisposition::Fatal,
            invalidated: Vec::new(),
        },
        "a fully committed window reports every durable outcome and settles Fatal"
    );
    let tip = fixture
        .handles
        .applied_tip_snapshot()
        .ok_or(TestError::Missing("committed tip"))?;
    assert_eq!(
        (tip.height, tip.hash),
        (2, Hash256::from(second.block_hash())),
        "the durably committed tip must stand with no rollback"
    );
    assert_refused_window_state(&fixture, &genesis)
}

// SYNC-04, SYNC-06, MPL-04
#[test]
fn a_partially_committed_window_halts_when_a_follower_refuses_settlement() -> Result<(), TestError>
{
    let genesis = Network::Regtest.genesis_block();
    let first =
        mined_block_with_prev_hash(genesis.block_hash(), 1, vec![regtest_fixture::coinbase(1)]);
    let invalid = mined_block_with_prev_hash(
        first.block_hash(),
        2,
        vec![regtest_fixture::coinbase(2), regtest_fixture::coinbase(3)],
    );
    let child =
        mined_block_with_prev_hash(invalid.block_hash(), 3, vec![regtest_fixture::coinbase(3)]);
    let payloads = vec![
        BlockImage::from_local(first.clone()),
        BlockImage::from_local(invalid.clone()),
        BlockImage::from_local(child.clone()),
    ];
    let fixture = refusal_window_fixture(&[first.clone(), invalid.clone(), child.clone()])?;
    let (observed, fixture) = drive_refused_window(fixture, payloads)?;
    assert_eq!(
        observed,
        ObservedWindow::Refused {
            applied: 1,
            disposition: WindowApplyDisposition::Fatal,
            invalidated: vec![
                Hash256::from(invalid.block_hash()),
                Hash256::from(child.block_hash()),
            ],
        },
        "a partially committed window keeps its durable applied prefix and invalidated set"
    );
    let tip = fixture
        .handles
        .applied_tip_snapshot()
        .ok_or(TestError::Missing("committed tip"))?;
    assert_eq!(
        (tip.height, tip.hash),
        (1, Hash256::from(first.block_hash())),
        "only the durably committed prefix stands with no rollback"
    );
    assert_refused_window_state(&fixture, &genesis)
}
