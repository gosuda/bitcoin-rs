use super::*;

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
        state
            .chainstate()
            .block_body_store()
            .ok_or_else(|| anyhow::anyhow!("running node has no body store"))?
            .load_block_body(0, hash)?
            .as_deref(),
        Some(consensus_bytes(&block).as_slice())
    );
    Ok(())
}

#[test]
fn preserved_bytes_apply_matches_lazy_serialization() -> anyhow::Result<()> {
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
        .apply_block(&block, Some(serialized))?;

    let body_a = state_a
        .chainstate()
        .block_body_store()
        .ok_or_else(|| anyhow::anyhow!("running node has no body store"))?
        .load_block_body(0, hash)?
        .ok_or_else(|| anyhow::anyhow!("apply_block body missing"))?;
    let body_b = state_b
        .chainstate()
        .block_body_store()
        .ok_or_else(|| anyhow::anyhow!("running node has no body store"))?
        .load_block_body(0, hash)?
        .ok_or_else(|| anyhow::anyhow!("preserved-byte apply body missing"))?;
    assert_eq!(body_a, body_b);
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
    let barrier = handles.transition_barrier();
    let transition = barrier.lock();
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

    state.chainstate().fail_closed_for_recovery();
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
    use bitcoin_rs_index::block_log::BlockLog;
    use bitcoin_rs_rpc::context::PruneService;
    use bitcoin_rs_storage::FlatFileBlockStore;
    use bitcoin_rs_storage::KvStore;
    use bitcoin_rs_storage::WriteBatch as _;
    use bitcoin_rs_storage::pruning::load_pruneheight;
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
    // The prune line is computed from what the pass actually deletes, so
    // seed one prunable body row at height 10: without it the pass deletes
    // nothing and never reaches the blocking body-store load.
    let mut seed = store.new_batch();
    seed.put(
        bitcoin_rs_storage::pruning::BLOCK_DATA_CF,
        &bitcoin_rs_storage::pruning::block_body_key(10, hash),
        &bitcoin_rs_storage::BlockFilePosition {
            file_no: 0,
            offset: 0,
            len: 1,
        }
        .encode(),
    );
    seed.put(
        bitcoin_rs_storage::pruning::BLOCK_DATA_CF,
        &bitcoin_rs_storage::block_file_max_height_key(0),
        &bitcoin_rs_storage::encode_block_file_max_height(10),
    );
    store.write(seed)?;
    let service = Arc::new(NodePruneService::new(
        Arc::clone(&store),
        block_files,
        body_handle,
        Arc::clone(&blocks),
        Arc::new(RwLock::new(HashMap::new())),
        authority_state.chainstate().prune_authority(),
        Arc::new(AtomicU32::new(11 + CORE_REORG_SAFETY_MARGIN)),
        Arc::new(bitcoin_rs_storage::RetentionRegistry::new()),
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
