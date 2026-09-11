use super::*;

#[test]
fn prune_service_is_absent_when_config_disables_pruning() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    config.storage.prune_target_mb = 0;

    let state = NodeState::open(config, None)?;

    assert!(state.prune_service().is_none());
    Ok(())
}

#[test]
fn apply_block_persists_body_under_pruning_key_when_pruning_disabled() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    config.storage.prune_target_mb = 0;
    let state = NodeState::open(config, None)?;
    let block = bitcoin_rs_primitives::Network::Regtest.genesis_block();
    let hash = Hash256::from_le_bytes(block.block_hash().as_bytes());

    assert!(state.prune_service().is_none());
    state.apply_block(&block)?;

    assert_eq!(
        state.blocks.read().first().map(|record| record.body_size),
        Some(consensus_bytes(&block).len())
    );
    assert_eq!(
        state.block_body_store.load_block_body(0, hash)?.as_deref(),
        Some(consensus_bytes(&block).as_slice())
    );
    Ok(())
}

#[test]
fn persisting_same_block_body_twice_appends_once() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    let state = NodeState::open(config, None)?;
    let hash = bitcoin_rs_primitives::Hash256::from_le_bytes(&[7_u8; 32]);
    let body = b"idempotent block body";

    state.block_body_store.persist_block_body(42, hash, body)?;
    let block_file = state.data_dir.join("blocks").join("blk00000.dat");
    let first_len = std::fs::metadata(&block_file)?.len();
    state.block_body_store.persist_block_body(42, hash, body)?;
    let second_len = std::fs::metadata(block_file)?.len();

    assert_eq!(second_len, first_len);
    assert_eq!(
        state.block_body_store.load_block_body(42, hash)?.as_deref(),
        Some(body.as_slice())
    );
    Ok(())
}

#[test]
fn apply_block_with_serialized_persists_same_body_as_apply_block() -> anyhow::Result<()> {
    let block = bitcoin_rs_primitives::Network::Regtest.genesis_block();
    let hash = Hash256::from_le_bytes(block.block_hash().as_bytes());
    let serialized = bytes::Bytes::from(consensus_bytes(&block));

    let dir_a = tempfile::tempdir()?;
    let mut config_a = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config_a.data_dir = dir_a.path().join("node-a");
    config_a.p2p.listen.clear();
    config_a.storage.prune_target_mb = 0;
    let state_a = NodeState::open(config_a, None)?;
    state_a.apply_block(&block)?;

    let dir_b = tempfile::tempdir()?;
    let mut config_b = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config_b.data_dir = dir_b.path().join("node-b");
    config_b.p2p.listen.clear();
    config_b.storage.prune_target_mb = 0;
    let state_b = NodeState::open(config_b, None)?;
    state_b
        .chainstate()
        .apply_block_with_serialized(&block, serialized)?;

    let body_a = state_a
        .block_body_store
        .load_block_body(0, hash)?
        .ok_or_else(|| anyhow::anyhow!("apply_block body missing"))?;
    let body_b = state_b
        .block_body_store
        .load_block_body(0, hash)?
        .ok_or_else(|| anyhow::anyhow!("apply_block_with_serialized body missing"))?;
    assert_eq!(body_a, body_b);
    Ok(())
}

#[test]
fn undo_pruning_keeps_records_the_durable_tip_still_needs() -> anyhow::Result<()> {
    fn hash(height: u32) -> anyhow::Result<bitcoin_rs_primitives::Hash256> {
        let byte =
            u8::try_from(height).map_err(|_| anyhow::anyhow!("test height {height} exceeds u8"))?;
        Ok(bitcoin_rs_primitives::Hash256::from_le_bytes(&[byte; 32]))
    }

    let dir = tempfile::tempdir()?;
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    config.storage.prune_target_mb = 1;
    let state = NodeState::open(config, None)?;
    publish_applied_tip_height(&state, 11 + CORE_REORG_SAFETY_MARGIN);

    for height in 10_u32..=12 {
        let hash = hash(height)?;
        state
            .block_body_store
            .persist_block_body(height, hash, b"block-body")?;
        state
            .chainstate()
            .undo_store
            .persist_undo(height, hash, b"undo-body")?;
        state.blocks.write().push(BlockRecord {
            hash: BlockHash::from(hash),
            height,
            body_size: 1,
            header: None,
            tx_count: 0,
            time: 0,
        });
    }

    // No checkpoint has been written, so nothing is durable above genesis.
    assert_eq!(
        state.durable_tip_height.load(Ordering::Acquire),
        0,
        "the fixture must have no durable checkpoint, or this proves nothing"
    );

    let Some(service) = state.prune_service() else {
        anyhow::bail!("prune service should exist when prune_target_mb > 0");
    };
    let result = service
        .prune_to_height(11)
        .map_err(|err| anyhow::anyhow!("prune failed: {err}"))?;

    assert_eq!(
        result.undo_rows_removed, 0,
        "no undo record may go while a crash would restore below all of them"
    );
    assert!(
        state.storage.stored_prune_undo(10, hash(10)?)?.is_some(),
        "the record a restore would need must survive"
    );
    Ok(())
}

#[test]
fn prune_service_deletes_seeded_storage_rows_and_advances_pruneheight() -> anyhow::Result<()> {
    fn hash(height: u32) -> anyhow::Result<bitcoin_rs_primitives::Hash256> {
        let byte =
            u8::try_from(height).map_err(|_| anyhow::anyhow!("test height {height} exceeds u8"))?;
        Ok(bitcoin_rs_primitives::Hash256::from_le_bytes(&[byte; 32]))
    }

    let dir = tempfile::tempdir()?;
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    config.storage.prune_target_mb = 1;
    let state = NodeState::open(config, None)?;
    publish_applied_tip_height(&state, 11 + CORE_REORG_SAFETY_MARGIN);

    for height in 10_u32..=12 {
        let hash = hash(height)?;
        state
            .block_body_store
            .persist_block_body(height, hash, b"block-body")?;
        state
            .chainstate()
            .undo_store
            .persist_undo(height, hash, b"undo-body")?;
        state.blocks.write().push(BlockRecord {
            hash: BlockHash::from(hash),
            height,
            body_size: 1,
            header: None,
            tx_count: 0,
            time: 0,
        });
    }

    // A node pruning old history has a durable tip far above it. Undo
    // records within the reorg-safety margin of that tip are kept, so the
    // durable tip has to clear height 11 by more than the margin for this
    // prune to touch anything. Without that the prune is correctly refused,
    // which the sibling test asserts.
    state
        .durable_tip_height
        .store(11 + CORE_REORG_SAFETY_MARGIN, Ordering::Release);

    let Some(service) = state.prune_service() else {
        anyhow::bail!("prune service should exist when prune_target_mb > 0");
    };
    let result = service
        .prune_to_height(11)
        .map_err(|err| anyhow::anyhow!("prune failed: {err}"))?;

    assert_eq!(result.pruneheight, 11);
    assert_eq!(result.block_rows_removed, 1);
    assert_eq!(result.undo_rows_removed, 1);
    assert!(state.storage.stored_prune_body(10, hash(10)?)?.is_none());
    assert!(state.storage.stored_prune_undo(10, hash(10)?)?.is_none());
    assert!(state.storage.stored_prune_body(11, hash(11)?)?.is_some());
    assert!(state.storage.stored_prune_undo(11, hash(11)?)?.is_some());
    assert!(state.storage.stored_prune_body(12, hash(12)?)?.is_some());
    assert!(state.storage.stored_prune_undo(12, hash(12)?)?.is_some());

    Ok(())
}

#[test]
fn prune_reclaims_whole_files_and_keeps_current_file() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    config.storage.prune_target_mb = 1;
    std::fs::create_dir_all(&config.data_dir)?;
    let blocks_dir = config.data_dir.join("blocks");
    std::fs::create_dir_all(&blocks_dir)?;
    let prunable_file = blocks_dir.join("blk00000.dat");
    let current_file = blocks_dir.join("blk00001.dat");
    std::fs::write(&prunable_file, [])?;
    std::fs::write(&current_file, [])?;
    let state = NodeState::open(config, None)?;
    publish_applied_tip_height(&state, 11 + CORE_REORG_SAFETY_MARGIN);
    // The prune is a no-op until a durable tip is published;
    // `bitcoin_rs_storage::pruning::stage_block_and_undo_prune` owns file selection.
    state
        .durable_tip_height
        .store(11 + CORE_REORG_SAFETY_MARGIN, Ordering::Release);
    let hash = bitcoin_rs_primitives::Hash256::from_le_bytes(&[10_u8; 32]);
    let position = bitcoin_rs_storage::BlockFilePosition {
        file_no: 0,
        offset: 0,
        len: 0,
    };
    state.storage.write_test_rows(&[
        (
            bitcoin_rs_storage::pruning::BLOCK_DATA_CF,
            bitcoin_rs_storage::pruning::block_body_key(10, hash).to_vec(),
            position.encode().to_vec(),
        ),
        (
            bitcoin_rs_storage::pruning::BLOCK_DATA_CF,
            bitcoin_rs_storage::block_file_max_height_key(0).to_vec(),
            bitcoin_rs_storage::encode_block_file_max_height(10).to_vec(),
        ),
    ])?;
    let Some(service) = state.prune_service() else {
        anyhow::bail!("prune service should exist when prune_target_mb > 0");
    };
    service
        .prune_to_height(11)
        .map_err(|error| anyhow::anyhow!("prune failed: {error}"))?;

    assert!(!prunable_file.exists());
    assert!(current_file.exists());
    assert!(state.storage.stored_prune_body(10, hash)?.is_none());
    let has_metadata = state
        .storage
        .read_test_row(
            bitcoin_rs_storage::pruning::BLOCK_DATA_CF,
            &bitcoin_rs_storage::block_file_max_height_key(0),
        )?
        .is_some();
    assert!(!has_metadata);
    Ok(())
}

/// Pruning a block file must reduce what the node reports as its disk size.
///
/// `getblockchaininfo.size_on_disk` used to be the sum of every block
/// record's `body_size`. Pruning does not remove records — it clears their
/// cached bodies and leaves the rest — so that sum could not move, and a
/// pruned node went on reporting bytes it no longer had, under the one field
/// an operator reads to check that pruning worked.
///
/// This asserts both halves: the store's figure falls by exactly the file
/// that was deleted, and the record sum does not move at all. The second is
/// what makes the first worth having.
#[test]
fn pruning_a_block_file_reduces_the_reported_disk_size() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    config.storage.prune_target_mb = 1;

    std::fs::create_dir_all(&config.data_dir)?;

    // Two files present before the store opens, so the earlier one is not
    // the append target and is therefore prunable. Same shape as
    // `prune_reclaims_whole_files_and_keeps_current_file`, but with bytes in
    // it, because bytes are what is being counted.
    let blocks_dir = config.data_dir.join("blocks");
    std::fs::create_dir_all(&blocks_dir)?;
    let prunable_file = blocks_dir.join("blk00000.dat");
    let prunable_bytes = vec![7_u8; 4_096];
    std::fs::write(&prunable_file, &prunable_bytes)?;
    std::fs::write(blocks_dir.join("blk00001.dat"), [])?;

    let state = NodeState::open(config, None)?;
    publish_applied_tip_height(&state, 11 + CORE_REORG_SAFETY_MARGIN);
    // The prune is a no-op until a durable tip is published;
    // `bitcoin_rs_storage::pruning::stage_block_and_undo_prune` owns file selection.
    state
        .durable_tip_height
        .store(11 + CORE_REORG_SAFETY_MARGIN, Ordering::Release);
    let block = bitcoin_rs_primitives::Network::Regtest.genesis_block();
    // The hash is not needed: this test counts bytes in files, not bodies.
    let record = BlockRecord::from_block(10, &block);
    let record_sum_before = u64::try_from(record.body_size)?;
    state.blocks.write().push(record);

    let Some(before) = state.block_body_store.disk_usage() else {
        anyhow::bail!("a flat-file store must report its usage");
    };
    assert!(
        before >= u64::try_from(prunable_bytes.len())?,
        "the fixture's bytes must be accounted for"
    );

    // Tell the pruner that file 0 tops out at height 10, so pruning to 11
    // makes it prunable.
    state.storage.write_test_rows(&[(
        bitcoin_rs_storage::pruning::BLOCK_DATA_CF,
        bitcoin_rs_storage::block_file_max_height_key(0).to_vec(),
        bitcoin_rs_storage::encode_block_file_max_height(10).to_vec(),
    )])?;

    let Some(service) = state.prune_service() else {
        anyhow::bail!("prune service should exist when prune_target_mb > 0");
    };
    service
        .prune_to_height(11)
        .map_err(|error| anyhow::anyhow!("prune failed: {error}"))?;

    assert!(!prunable_file.exists(), "the fixture must actually prune");
    let Some(after) = state.block_body_store.disk_usage() else {
        anyhow::bail!("a flat-file store must report its usage");
    };
    assert_eq!(
        after,
        before.saturating_sub(u64::try_from(prunable_bytes.len())?),
        "the reported size must fall by exactly the file that was deleted"
    );

    // The number this replaces, unmoved — which is the defect.
    let record_sum_after = state.blocks.read().iter().fold(0_u64, |total, entry| {
        total.saturating_add(u64::try_from(entry.body_size).unwrap_or(0))
    });
    assert_eq!(
        record_sum_after, record_sum_before,
        "the block-record sum cannot see pruning, which is why it is not \
         what size_on_disk reports"
    );
    Ok(())
}

#[test]
fn manual_prune_removes_pruned_block_transactions_from_cache() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    config.storage.prune_target_mb = 1;
    let state = NodeState::open(config, None)?;
    publish_applied_tip_height(&state, 11 + CORE_REORG_SAFETY_MARGIN);

    let pruned_block = bitcoin_rs_primitives::Network::Regtest.genesis_block();
    let pruned_hash = Hash256::from_le_bytes(pruned_block.block_hash().as_bytes());
    state
        .block_body_store
        .persist_block_body(10, pruned_hash, &consensus_bytes(&pruned_block))?;
    state
        .chainstate()
        .undo_store
        .persist_undo(10, pruned_hash, b"undo-body")?;
    state
        .blocks
        .write()
        .push(BlockRecord::from_block(10, &pruned_block));

    let pruned_tx = pruned_block.txs[0].clone();
    let pruned_txid = pruned_tx.txid();
    let unrelated_tx = Tx {
        version: 2,
        lock_time: LockTime::from_consensus(0),
        inputs: Vec::new(),
        outputs: Vec::new(),
    };
    let unrelated_txid = unrelated_tx.txid();

    {
        let mut transactions = state.transactions.write();
        transactions.insert(pruned_txid, pruned_tx);
        transactions.insert(unrelated_txid, unrelated_tx);
    }

    let Some(service) = state.prune_service() else {
        anyhow::bail!("prune service should exist when prune_target_mb > 0");
    };
    // Pruning cannot evict cached transactions while their block still lies
    // above the durable checkpoint's reorg-retention floor (ARCH-07).
    service
        .prune_to_height(11)
        .map_err(|err| anyhow::anyhow!("prune failed: {err}"))?;
    assert!(state.transactions.read().contains_key(&pruned_txid));
    assert!(state.transactions.read().contains_key(&unrelated_txid));

    // The synthetic applied-tip fixture must also publish durability before
    // any block below the requested height becomes eligible for pruning.
    state
        .durable_tip_height
        .store(11 + CORE_REORG_SAFETY_MARGIN, Ordering::Release);
    service
        .prune_to_height(11)
        .map_err(|err| anyhow::anyhow!("prune failed: {err}"))?;

    let transactions = state.transactions.read();
    assert!(!transactions.contains_key(&pruned_txid));
    assert!(transactions.contains_key(&unrelated_txid));
    Ok(())
}

#[test]
fn prune_service_restores_persisted_pruneheight_on_reopen() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    config.storage.prune_target_mb = 1;

    {
        let state = NodeState::open(config.clone(), None)?;
        publish_applied_tip_height(&state, 11 + CORE_REORG_SAFETY_MARGIN);
        let Some(service) = state.prune_service() else {
            anyhow::bail!("prune service should exist when prune_target_mb > 0");
        };
        let result = service
            .prune_to_height(11)
            .map_err(|err| anyhow::anyhow!("prune failed: {err}"))?;
        assert_eq!(result.pruneheight, 11);
    }

    let reopened = NodeState::open(config, None)?;
    let Some(service) = reopened.prune_service() else {
        anyhow::bail!("prune service should exist when prune_target_mb > 0");
    };
    assert_eq!(service.status().pruneheight, Some(11));

    Ok(())
}

#[test]
fn prune_waits_for_chain_transition_and_revalidates_applied_tip() -> anyhow::Result<()> {
    use std::time::Duration;

    let dir = tempfile::tempdir()?;
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    config.storage.prune_target_mb = 1;
    let state = NodeState::open(config.clone(), None)?;
    publish_applied_tip_height(&state, 11 + CORE_REORG_SAFETY_MARGIN);
    let Some(service) = state.prune_service() else {
        anyhow::bail!("prune service should exist when prune_target_mb > 0");
    };

    let handles = state.chainstate();
    let transition = handles.chain_transition.lock();
    let (started_tx, started_rx) = std::sync::mpsc::sync_channel(1);
    let (done_tx, done_rx) = std::sync::mpsc::sync_channel(1);
    let (done_while_locked, result) = std::thread::scope(|scope| -> anyhow::Result<_> {
        let service = Arc::clone(&service);
        let worker = scope.spawn(move || {
            let _ = started_tx.send(());
            let result = service.prune_to_height(11);
            let _ = done_tx.send(());
            result
        });
        started_rx.recv_timeout(Duration::from_secs(5))?;
        let done_while_locked = done_rx.recv_timeout(Duration::from_millis(100));
        publish_applied_tip_height(&state, 10 + CORE_REORG_SAFETY_MARGIN);
        drop(transition);
        let result = worker
            .join()
            .map_err(|_| anyhow::anyhow!("prune worker panicked"))?;
        Ok((done_while_locked, result))
    })?;
    let status_after = service.status();
    drop(service);
    drop(handles);
    drop(state);
    let reopened = NodeState::open(config, None)?;
    let Some(reopened_service) = reopened.prune_service() else {
        anyhow::bail!("prune service should exist after reopen");
    };

    assert!(
        matches!(
            done_while_locked,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ),
        "pruning entered while another chain transition held authority"
    );
    assert!(
        matches!(
            &result,
            Err(PruneServiceError::Failed(message))
                if message == "prune height is within reorg safety margin"
        ),
        "pruning did not reject the tip observed under authority: {result:?}"
    );
    assert_eq!(status_after.pruneheight, None);
    assert_eq!(reopened_service.status().pruneheight, None);
    Ok(())
}

#[test]
fn prune_refuses_after_apply_admission_closes() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    config.storage.prune_target_mb = 1;
    let state = NodeState::open(config, None)?;
    publish_applied_tip_height(&state, 11 + CORE_REORG_SAFETY_MARGIN);
    let Some(service) = state.prune_service() else {
        anyhow::bail!("prune service should exist when prune_target_mb > 0");
    };

    state.apply_handles.admission.close_permanently();
    let result = service.prune_to_height(11);

    assert!(
        matches!(
            &result,
            Err(PruneServiceError::Failed(message))
                if message == "block apply rejected because clean shutdown has begun"
        ),
        "pruning ignored closed chain-mutation admission: {result:?}"
    );
    assert_eq!(service.status().pruneheight, None);
    Ok(())
}

/// Overlapping prune calls must commit in acquisition order.
///
/// A lower request blocks inside body-store load while holding
/// `pruneheight`; a higher contender must neither enter that load nor
/// finish until the lower call releases, and both persisted and in-memory
/// pruneheight end at the higher value.
#[cfg(feature = "fjall")]
#[allow(clippy::too_many_lines)]
#[test]
fn prune_to_height_serializes_overlapping_calls() -> anyhow::Result<()> {
    use super::super::prune::load_pruneheight;
    use bitcoin_rs_rpc::context::{BlockLog, PruneService};
    use bitcoin_rs_storage::FlatFileBlockStore;
    use parking_lot::RwLock;
    use std::sync::Barrier;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::{AtomicBool, AtomicU32};
    use std::time::Duration;

    struct BlockingPruneBodyStore {
        entered: Barrier,
        release: Barrier,
        block_once: AtomicBool,
        loads: AtomicUsize,
    }

    impl bitcoin_rs_storage::block_body::BlockBodyStore for BlockingPruneBodyStore {
        fn load_block_body(
            &self,
            _height: u32,
            _hash: bitcoin_rs_primitives::Hash256,
        ) -> Result<Option<Vec<u8>>, bitcoin_rs_storage::StorageError> {
            self.loads.fetch_add(1, Ordering::AcqRel);
            if self.block_once.swap(false, Ordering::AcqRel) {
                self.entered.wait();
                self.release.wait();
            }
            Ok(None)
        }

        fn persist_block_body(
            &self,
            _height: u32,
            _hash: bitcoin_rs_primitives::Hash256,
            _body: &[u8],
        ) -> Result<(), bitcoin_rs_storage::StorageError> {
            Ok(())
        }

        fn sync(&self) -> Result<(), bitcoin_rs_storage::StorageError> {
            Ok(())
        }
    }

    let dir = tempfile::tempdir()?;
    let mut authority_config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    authority_config.data_dir = dir.path().join("authority");
    authority_config.p2p.listen.clear();
    let authority_state = NodeState::open(authority_config, None)?;
    publish_applied_tip_height(&authority_state, 12 + CORE_REORG_SAFETY_MARGIN);
    let data_dir = dir.path().join("node");
    std::fs::create_dir_all(data_dir.join("chainstate"))?;
    let store = Arc::new(bitcoin_rs_storage::FjallStore::open(
        data_dir.join("chainstate"),
    )?);
    let block_files = Arc::new(FlatFileBlockStore::open(&data_dir)?);
    let body_store = Arc::new(BlockingPruneBodyStore {
        entered: Barrier::new(2),
        release: Barrier::new(2),
        block_once: AtomicBool::new(true),
        loads: AtomicUsize::new(0),
    });
    let body_handle: Arc<dyn bitcoin_rs_storage::block_body::BlockBodyStore> = body_store.clone();
    let blocks = Arc::new(RwLock::new(BlockLog::new()));
    let hash = bitcoin_rs_primitives::Hash256::from_le_bytes(&[10_u8; 32]);
    blocks.write().push(BlockRecord {
        hash: BlockHash::from(hash),
        height: 10,
        body_size: 1,
        header: None,
        tx_count: 1,
        time: 0,
    });
    let service = Arc::new(NodePruneService::new(
        Arc::clone(&store),
        block_files,
        body_handle,
        Arc::clone(&blocks),
        Arc::new(RwLock::new(HashMap::new())),
        authority_state.chainstate().prune_authority(),
        Arc::new(AtomicU32::new(11 + CORE_REORG_SAFETY_MARGIN)),
    )?);

    let (started_tx, started_rx) = std::sync::mpsc::sync_channel(1);
    let (done_tx, done_rx) = std::sync::mpsc::sync_channel(1);
    std::thread::scope(|scope| -> anyhow::Result<()> {
        let lower_service = Arc::clone(&service);
        let lower = scope.spawn(move || lower_service.prune_to_height(11));
        body_store.entered.wait();

        let higher_service = Arc::clone(&service);
        let higher = scope.spawn(move || {
            let _ = started_tx.send(());
            let result = higher_service.prune_to_height(12);
            let _ = done_tx.send(());
            result
        });
        let higher_started = started_rx.recv_timeout(Duration::from_secs(5));
        let higher_done = done_rx.recv_timeout(Duration::from_millis(100));
        let loads_while_lower_blocked = body_store.loads.load(Ordering::Acquire);
        body_store.release.wait();
        let lower_join = lower.join();
        let higher_join = higher.join();
        higher_started.map_err(|error| anyhow::anyhow!("higher prune did not start: {error}"))?;
        let lower_result = lower_join
            .map_err(|_| anyhow::anyhow!("lower prune panicked"))?
            .map_err(|err| anyhow::anyhow!("lower prune failed: {err}"))?;
        let higher_result = higher_join
            .map_err(|_| anyhow::anyhow!("higher prune panicked"))?
            .map_err(|err| anyhow::anyhow!("higher prune failed: {err}"))?;
        assert!(
            matches!(higher_done, Err(std::sync::mpsc::RecvTimeoutError::Timeout)),
            "higher prune committed while lower still held the pruneheight lock; done_rx={higher_done:?}"
        );
        assert_eq!(
            loads_while_lower_blocked, 1,
            "higher prune must not enter body-store load while lower holds pruneheight; loads={loads_while_lower_blocked}"
        );
        assert_eq!(lower_result.pruneheight, 11);
        assert_eq!(higher_result.pruneheight, 12);
        Ok(())
    })?;

    assert_eq!(service.status().pruneheight, Some(12));
    assert_eq!(load_pruneheight(&*store)?, Some(12));
    Ok(())
}
