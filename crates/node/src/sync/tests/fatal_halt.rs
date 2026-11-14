#![allow(clippy::expect_used)]

use std::sync::Arc;
use std::time::Duration;

use bitcoin_rs_consensus::primitives::{Block, BlockImage, Network};
use bitcoin_rs_execution::chain::{BlockTree, NodeStatus, regtest_fixture};
use bitcoin_rs_storage::memory_kv::MemoryKvStore;
use bitcoin_rs_storage::pruning::{HistoryAccess, RetentionBudget};
use bitcoin_rs_storage::utxo::UtxoSet;
use bitcoin_rs_storage::{
    CoinStore, CommitAuthority, KvDurableHeadStore, KvStore, KvUndoStore, MandatoryRetention,
    PersistFault, RetentionRegistry,
};
use crossbeam_channel::{bounded, unbounded};

use crate::event_loop::EventLoop;
use crate::test_support::TestError;

fn failing_commit_chain(
    depth: u32,
) -> Result<(Arc<bitcoin_rs_execution::Chainstate>, Vec<Block>), TestError> {
    use bitcoin_rs_execution::{Chainstate, ChainstateParts, ChainstateRole, ValidationMode};

    let genesis = Network::Regtest.genesis_block();
    let mut tree = BlockTree::new();
    let mut parent = tree.insert_node(None, genesis.header, NodeStatus::HeaderValid)?;
    let mut blocks = Vec::new();
    let mut prev_hash = genesis.block_hash();
    for height in 1..=depth {
        let block = regtest_fixture::mined_block_with_prev_hash(
            prev_hash,
            height,
            vec![regtest_fixture::coinbase(height)],
        )?;
        prev_hash = block.block_hash();
        parent = tree.insert_node(Some(parent), block.header, NodeStatus::HeaderValid)?;
        blocks.push(block);
    }
    let retention = Arc::new(RetentionRegistry::new());
    let mem_store = Arc::new(MemoryKvStore::default());
    let durable_head = Arc::new(KvDurableHeadStore::new(Arc::clone(&mem_store)));
    let undo_store = Arc::new(KvUndoStore::new(Arc::clone(&mem_store)));
    let dyn_store: Arc<dyn KvStore> = mem_store.clone();
    let coins = Arc::new(CoinStore::open(Arc::clone(&dyn_store), 64 * 1024 * 1024));
    let commit_authority = Arc::new(CommitAuthority::new(dyn_store, Arc::clone(&coins)));
    let handles = Arc::new(Chainstate::from_parts(ChainstateParts {
        network: Network::Regtest,
        block_tree: tree,
        restored_applied_tip: None,
        utxo: Arc::new(UtxoSet::new()),
        coin_stats: Arc::new(bitcoin_rs_storage::utxo::stats::CoinStatsListener::new(
            bitcoin_rs_storage::utxo::stats::CoinStats::default(),
        )),
        chain_events: Arc::new(bitcoin_rs_execution::events::ChainEventPublisher::detached(
            0,
        )),
        block_body_store: None,
        undo_store,
        durable_head,
        coins,
        commit_authority,
        chain_transition: bitcoin_rs_execution::chain::TransitionDomain::new().authority(),
        assume_valid_height: 0,
        validation_mode: ValidationMode::AssumeValid,
        validation_engine: bitcoin_rs_consensus::ValidationEngine::Native,
        script_cache: None,
        capture_rawtx: false,
        capture_block_bytes: false,
        retention: MandatoryRetention::new(Arc::clone(&retention)),
        window_limits: bitcoin_rs_execution::default_window_limits_source(),
        history: HistoryAccess::new(retention, RetentionBudget::from_blocks(288)),
        role: ChainstateRole::Ordinary,
    }));
    handles
        .apply_block(&BlockImage::from_local(genesis))
        .map_err(|error| TestError::Apply(Box::new(error)))?;
    mem_store.arm_persist_fault(PersistFault::FailApply);
    Ok((handles, blocks))
}

// SYNC-04, SYNC-06
#[test]
fn failed_durable_commit_halts_apply_and_trips_the_shutdown_latch() -> Result<(), TestError> {
    let (handles, blocks) = failing_commit_chain(2)?;
    let followers = crate::chain_effects::ChainFollowers::noop();
    let peers = Arc::new(bitcoin_rs_wire::PeerTable::new());
    let (_inbound_headers_tx, inbound_headers_rx) = unbounded();
    let (inbound_blocks_tx, inbound_blocks_rx) = unbounded();
    let ibd = Arc::new(bitcoin_rs_execution::chain::InitialBlockDownload::new(
        handles.applied_tip_reader(),
        handles.block_tree_reader(),
    ));
    let sync = Arc::new(crate::sync::block_sync(crate::sync::BlockSyncInputs {
        handles: Arc::clone(&handles),
        followers,
        peer_table: peers,
        inbound_headers_rx,
        inbound_blocks_rx,
        ibd,
        assumeutxo: None,
        budget: Arc::new(crate::budget::NodeBudget::from_chainstate_cache_budget(
            bitcoin_rs_storage::split_chainstate_cache_budget(16),
            1,
        )),
    }));

    inbound_blocks_tx
        .send(bitcoin_rs_wire::InboundBlock::from_local(blocks[0].clone()))
        .map_err(|_| TestError::Missing("inbound block channel closed"))?;
    sync.tick();
    assert!(
        handles.is_closed_for_recovery(),
        "a failed durable commit must settle fatal and close the chainstate for recovery"
    );
    assert_eq!(
        handles.applied_tip_snapshot().map(|tip| tip.height),
        Some(0),
        "failed undo persistence must not publish a tip"
    );

    for block in [&blocks[1], &blocks[0]] {
        inbound_blocks_tx
            .send(bitcoin_rs_wire::InboundBlock::from_local(block.clone()))
            .map_err(|_| TestError::Missing("inbound block channel closed"))?;
    }
    sync.tick();
    assert!(
        handles.is_closed_for_recovery(),
        "the recovery closure must stay raised; a closed chainstate never retries apply"
    );
    assert_eq!(
        handles.applied_tip_snapshot().map(|tip| tip.height),
        Some(0),
        "a halted sync must not commit the redelivered blocks"
    );

    let latch = Arc::new(bitcoin_rs_consensus::latch::LatchWriter::new());
    let verify_reader = latch.reader();
    let loop_reader = latch.reader();
    let shutdown_for_request = Arc::clone(&latch);
    let shutdown_requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let requests_for_closure = Arc::clone(&shutdown_requests);
    let (wake_tx, wake_rx) = bounded::<()>(1);
    let (requested_tx, requested_rx) = bounded::<()>(1);
    let loop_handle = EventLoop::with_sync_wake(Arc::clone(&sync), wake_rx);
    let spinner = std::thread::Builder::new()
        .name("fatal-halt-spinner".into())
        .spawn(move || {
            loop_handle.spin(&loop_reader, move || {
                requests_for_closure.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                shutdown_for_request.trigger();
                let _ = requested_tx.try_send(());
            });
        })?;
    wake_tx
        .send(())
        .map_err(|_| TestError::Missing("event loop stopped before the wake"))?;
    match requested_rx.recv_timeout(Duration::from_secs(5)) {
        Ok(()) => {}
        Err(_) => {
            latch.trigger();
            let _ = spinner.join();
            return Err(TestError::Missing(
                "the apply halt never reached the shutdown latch",
            ));
        }
    }
    spinner
        .join()
        .map_err(|_| TestError::Missing("event loop thread panicked"))?;
    assert_eq!(
        shutdown_requests.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "one halt settlement must request shutdown exactly once"
    );
    assert!(
        verify_reader.is_triggered(),
        "requesting shutdown must trigger the node shutdown latch"
    );
    Ok(())
}
