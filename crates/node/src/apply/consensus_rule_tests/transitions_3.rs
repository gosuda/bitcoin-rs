use super::*;

#[test]
fn invalidate_block_holds_chain_transition_through_preflight_and_disconnect()
-> Result<(), Box<dyn std::error::Error>> {
    let utxo = Arc::new(UtxoSet::new());
    let mut handles = apply_handles_without_tx_index(Network::Regtest, Arc::clone(&utxo));
    let genesis = Network::Regtest.genesis_block();
    let genesis_hash = Hash256::from(genesis.block_hash());
    let genesis_tip = applied_header_tip(&handles, genesis_hash, &genesis, 0)?;
    handles.applied_tip.store(Some(Arc::new(genesis_tip)));

    let block = mined_block_with_prev_hash_and_transactions(
        genesis.block_hash(),
        vec![coinbase_transaction(1)],
    )?;
    let raw = bytes::Bytes::from(consensus_bytes(&block));
    let applied = handles
        .apply_block_with_serialized(&block, raw.clone())?
        .tip;

    let store = Arc::new(BlockingBodyStore {
        body: raw.to_vec(),
        entered: std::sync::Barrier::new(2),
        release: std::sync::Barrier::new(2),
        block_once: AtomicBool::new(true),
    });
    let body_handle: Arc<dyn bitcoin_rs_storage::block_body::BlockBodyStore> = store.clone();
    handles.block_body_store = Some(body_handle);

    let worker_handles = handles.clone();
    let contender_handles = handles.clone();
    let (started_tx, started_rx) = std::sync::mpsc::sync_channel(1);
    let (acquired_tx, acquired_rx) = std::sync::mpsc::sync_channel(1);
    std::thread::scope(|scope| -> Result<(), Box<dyn std::error::Error>> {
        let invalidator = scope.spawn(move || {
            crate::reorg::invalidate_block(
                &worker_handles,
                &crate::chain_effects::ChainFollowers::noop(),
                applied.hash,
            )
        });
        store.entered.wait();

        let contender = scope.spawn(move || {
            let _ = started_tx.send(());
            let transition = contender_handles.lock_transition();
            let acquired = transition.is_ok();
            let _ = acquired_tx.send(acquired);
            drop(transition);
            if acquired {
                Ok(())
            } else {
                Err(ApplyError::Shutdown)
            }
        });
        started_rx.recv_timeout(std::time::Duration::from_secs(5))?;
        assert!(
            matches!(
                acquired_rx.recv_timeout(std::time::Duration::from_millis(100)),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout)
            ),
            "a competing transition entered while invalidation was preloading"
        );

        store.release.wait();
        invalidator
            .join()
            .map_err(|_| std::io::Error::other("invalidation worker panicked"))??;
        assert!(acquired_rx.recv_timeout(std::time::Duration::from_secs(5))?);
        contender
            .join()
            .map_err(|_| std::io::Error::other("transition contender panicked"))??;
        Ok(())
    })?;

    assert_eq!(
        handles.applied_tip.load_full().map(|tip| tip.hash),
        Some(genesis_hash)
    );
    assert_eq!(
        handles.block_tree.read().node(applied.tip_id)?.status,
        NodeStatus::Invalid
    );
    Ok(())
}

#[test]
fn connected_sequence_event_observes_the_published_applied_tip()
-> Result<(), Box<dyn std::error::Error>> {
    let handles = apply_handles_without_tx_index(Network::Regtest, Arc::new(UtxoSet::new()));
    let genesis = Network::Regtest.genesis_block();
    let genesis_hash = Hash256::from(genesis.block_hash());
    let genesis_tip = applied_header_tip(&handles, genesis_hash, &genesis, 0)?;
    handles.applied_tip.store(Some(Arc::new(genesis_tip)));
    let block = mined_block_with_prev_hash_and_transactions(
        genesis.block_hash(),
        vec![coinbase_transaction(5)],
    )?;
    let expected = Hash256::from(block.block_hash());
    let publisher = Arc::new(AppliedTipVisiblePublisher {
        applied_tip: Arc::clone(&handles.applied_tip),
        expected,
        seen: Mutex::new(Vec::new()),
    });
    let publisher_handle: Arc<dyn crate::ZmqPublisher> = publisher.clone();
    let followers = zmq_followers(publisher_handle);

    apply_followed(&handles, &followers, &block)?;

    assert_eq!(*publisher.seen.lock(), vec![expected]);
    Ok(())
}

/// `ARCH-07`: follower dispatch must run before the transition lock is
/// released, so a later connect cannot publish derived effects first.
#[test]
fn follower_dispatch_holds_the_chain_transition() -> Result<(), Box<dyn std::error::Error>> {
    let handles = apply_handles_without_tx_index(Network::Regtest, Arc::new(UtxoSet::new()));
    let genesis = Network::Regtest.genesis_block();
    let genesis_hash = Hash256::from(genesis.block_hash());
    let genesis_tip = applied_header_tip(&handles, genesis_hash, &genesis, 0)?;
    handles.applied_tip.store(Some(Arc::new(genesis_tip)));
    let block = mined_block_with_prev_hash_and_transactions(
        genesis.block_hash(),
        vec![coinbase_transaction(6)],
    )?;
    let entered = std::sync::Arc::new(std::sync::Barrier::new(2));
    let release = std::sync::Arc::new(std::sync::Barrier::new(2));
    let publisher = Arc::new(TransitionHeldPublisher {
        entered: Arc::clone(&entered),
        release: Arc::clone(&release),
    });
    let publisher_handle: Arc<dyn crate::ZmqPublisher> = publisher;
    let followers = zmq_followers(publisher_handle);

    std::thread::scope(|scope| -> Result<(), Box<dyn std::error::Error>> {
        let worker_handles = handles.clone();
        let worker_followers = followers.clone();
        let worker =
            scope.spawn(move || apply_followed(&worker_handles, &worker_followers, &block));
        entered.wait();
        assert!(
            handles.chain_transition.try_lock().is_none(),
            "a competing transition must not enter during follower dispatch"
        );
        release.wait();
        worker
            .join()
            .map_err(|_| std::io::Error::other("apply worker panicked"))??;
        Ok(())
    })?;
    Ok(())
}

#[test]
fn a_disconnect_body_store_failure_moves_nothing() -> Result<(), Box<dyn std::error::Error>> {
    let ReorgBodyLoadingFixture {
        handles,
        utxo,
        bodies,
        target,
        losing,
        applied,
    } = reorg_body_loading_fixture()?;
    bodies
        .failed_reads
        .write()
        .insert((applied.height, applied.hash));
    let tree_tip_before = handles
        .block_tree
        .read()
        .tip()
        .map(|tip| (tip.tip_id, tip.height, tip.hash));
    let utxo_len_before = utxo.len();
    let marker_before = handles.undo_store.load_disconnect_marker()?;

    let outcome = crate::reorg::switch_to_branch(
        &handles,
        &crate::chain_effects::ChainFollowers::noop(),
        target,
        |_| None,
        |_| {},
    );
    assert!(
        matches!(
            outcome,
            Err(crate::reorg::ReorgError::BodyStore {
                hash,
                height,
                source: StorageError::Backend(ref message),
            }) if hash == applied.hash
                && height == applied.height
                && message == "injected block-body read failure"
        ),
        "disconnect body storage failure must retain its typed error, got {outcome:?}"
    );
    assert_reorg_load_failure_preserved_state(
        &handles,
        &utxo,
        &losing,
        &applied,
        tree_tip_before,
        utxo_len_before,
    );
    assert_eq!(
        handles.undo_store.load_disconnect_marker()?,
        marker_before,
        "body storage failure must not arm the disconnect marker"
    );
    Ok(())
}

#[test]
fn a_disconnect_body_decode_failure_moves_nothing() -> Result<(), Box<dyn std::error::Error>> {
    let ReorgBodyLoadingFixture {
        handles,
        utxo,
        bodies,
        target,
        losing,
        applied,
    } = reorg_body_loading_fixture()?;
    bodies
        .bodies
        .write()
        .insert((applied.height, applied.hash), vec![0]);
    let tree_tip_before = handles
        .block_tree
        .read()
        .tip()
        .map(|tip| (tip.tip_id, tip.height, tip.hash));
    let utxo_len_before = utxo.len();
    let marker_before = handles.undo_store.load_disconnect_marker()?;

    let outcome = crate::reorg::switch_to_branch(
        &handles,
        &crate::chain_effects::ChainFollowers::noop(),
        target,
        |_| None,
        |_| {},
    );
    assert!(
        matches!(
            outcome,
            Err(crate::reorg::ReorgError::BodyDecode { hash, height, .. })
                if hash == applied.hash && height == applied.height
        ),
        "malformed disconnect body must retain its typed decode error, got {outcome:?}"
    );
    assert_reorg_load_failure_preserved_state(
        &handles,
        &utxo,
        &losing,
        &applied,
        tree_tip_before,
        utxo_len_before,
    );
    assert_eq!(
        handles.undo_store.load_disconnect_marker()?,
        marker_before,
        "body decode failure must not arm the disconnect marker"
    );
    Ok(())
}

#[test]
fn a_deep_reorg_deeper_than_the_stream_window_lands_on_the_fork_tip()
-> Result<(), Box<dyn std::error::Error>> {
    let utxo = Arc::new(UtxoSet::new());
    let mut handles = apply_handles_without_tx_index(Network::Regtest, Arc::clone(&utxo));
    let bodies = Arc::new(MapBodyStore::default());
    handles.block_body_store = Some(bodies.clone());

    let genesis = Network::Regtest.genesis_block();
    let genesis_hash = Hash256::from(genesis.block_hash());
    let genesis_tip = applied_header_tip(&handles, genesis_hash, &genesis, 0)?;
    handles.applied_tip.store(Some(Arc::new(genesis_tip)));

    // Build a 20-block old chain — deeper than DISCONNECT_STREAM_WINDOW (8).
    let mut prev = genesis.block_hash();
    for seed in 1_u8..=20 {
        let block =
            mined_block_with_prev_hash_and_transactions(prev, vec![coinbase_transaction(seed)])?;
        let raw = bytes::Bytes::from(consensus_bytes(&block));
        let tip = handles
            .apply_block_with_serialized(&block, raw.clone())?
            .tip;
        bodies
            .bodies
            .write()
            .insert((tip.height, tip.hash), raw.to_vec());
        prev = block.block_hash();
    }

    // Build a 21-block fork from genesis (heavier by one block).
    let mut fork_prev = genesis.block_hash();
    let mut fork_target = None;
    for (height, seed) in (1_u32..=21).zip(101_u8..=121) {
        let block = mined_block_with_prev_hash_and_transactions(
            fork_prev,
            vec![coinbase_transaction(seed)],
        )?;
        let hash = Hash256::from(block.block_hash());
        bodies
            .bodies
            .write()
            .insert((height, hash), consensus_bytes(&block));
        let mut tree = handles.block_tree.write();
        fork_target = Some(tree.insert_header(block.header, NodeStatus::HeaderValid)?);
        fork_prev = block.block_hash();
    }
    let fork_target = fork_target.ok_or_else(|| anyhow::anyhow!("fork has no target"))?;
    let fork_tip_hash = Hash256::from(fork_prev);

    crate::reorg::switch_to_branch(
        &handles,
        &crate::chain_effects::ChainFollowers::noop(),
        fork_target,
        |_| None,
        |_| {},
    )?;

    assert_eq!(
        handles.applied_tip.load_full().map(|tip| tip.hash),
        Some(fork_tip_hash),
        "deep reorg must land on the fork tip"
    );
    assert_eq!(
        handles.applied_tip.load_full().map(|tip| tip.height),
        Some(21),
        "deep reorg must reach fork height"
    );
    // 21 fork coinbase outputs (genesis coinbase was never applied to the
    // UTXO set — only the 20 old blocks were, and they were disconnected).
    assert_eq!(
        utxo.len(),
        21,
        "UTXO set must contain exactly the fork coinbase outputs"
    );
    Ok(())
}
