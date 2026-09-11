use super::*;

#[test]
fn a_body_read_failure_mid_rollback_reports_disconnect_body_lost_not_panic()
-> Result<(), Box<dyn std::error::Error>> {
    let utxo = Arc::new(UtxoSet::new());
    let mut handles = apply_handles_without_tx_index(Network::Regtest, Arc::clone(&utxo));
    let bodies = Arc::new(MapBodyStore::default());
    handles.block_body_store = Some(bodies.clone());

    let genesis = Network::Regtest.genesis_block();
    let genesis_hash = Hash256::from(genesis.block_hash());
    let genesis_tip = applied_header_tip(&handles, genesis_hash, &genesis, 0)?;
    handles.applied_tip.store(Some(Arc::new(genesis_tip)));

    // Build a 20-block old chain.
    let mut prev = genesis.block_hash();
    let mut old_tips = Vec::new();
    for seed in 1_u8..=20 {
        let block =
            mined_block_with_prev_hash_and_transactions(prev, vec![coinbase_transaction(seed)])?;
        let raw = bytes::Bytes::from(consensus_bytes(&block));
        let tip = handles.apply_block_with_serialized(&block, raw)?.tip;
        old_tips.push(tip);
        prev = block.block_hash();
    }

    // Build a 21-block fork from genesis.
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

    // Mark the body at height 5 (16th in the tip-down disconnect list,
    // inside the second window of 8) to fail on its second read. The
    // preflight pass reads it once (succeeds); the execution pass reads
    // it again (fails), proving the mid-rollback recovery path.
    let target_tip = &old_tips[4]; // height 5
    bodies
        .fail_on_second_read
        .write()
        .insert((target_tip.height, target_tip.hash));

    let outcome = crate::reorg::switch_to_branch(
        &handles,
        &crate::chain_effects::ChainFollowers::noop(),
        fork_target,
        |_| None,
        |_| {},
    );

    // With DISCONNECT_STREAM_WINDOW = 8, the first window (heights 20..13)
    // disconnects fully (8 blocks), then the second window's load fails at
    // height 5. The chain is coherent at height 12.
    let Err(crate::reorg::ReorgError::DisconnectBodyLost {
        disconnected,
        stopped_at,
        ..
    }) = outcome
    else {
        panic!("expected DisconnectBodyLost, got {outcome:?}");
    };
    assert_eq!(
        disconnected, 8,
        "first window of 8 must disconnect before the second window's load fails"
    );
    assert_eq!(
        stopped_at, 12,
        "tip must be at height 12 after 8 disconnects from height 20"
    );
    assert_eq!(
        handles.applied_tip.load_full().map(|tip| tip.height),
        Some(12),
        "applied tip must be at the height reached by the completed window"
    );
    // MPL-04: the completed disconnect prefix is a stable chain, even
    // when the next window cannot load its bodies.
    assert_eq!(utxo.len(), 12);
    assert!(
        handles.mempool_gateway.stable_generation().is_some(),
        "mid-rollback body loss must reopen admission at the committed prefix"
    );
    bodies
        .fail_on_second_read
        .write()
        .remove(&(target_tip.height, target_tip.hash));
    crate::reorg::switch_to_branch(
        &handles,
        &crate::chain_effects::ChainFollowers::noop(),
        fork_target,
        |_| None,
        |_| {},
    )?;
    assert_eq!(
        handles.applied_tip.load_full().map(|tip| tip.hash),
        Some(Hash256::from(fork_prev)),
        "retry must resume from the committed prefix and reach the fork tip"
    );
    assert_eq!(utxo.len(), 21);
    assert!(handles.mempool_gateway.stable_generation().is_some());
    Ok(())
}

#[test]
fn a_closed_admission_refuses_every_chainstate_mutation() -> Result<(), Box<dyn std::error::Error>>
{
    let utxo = Arc::new(UtxoSet::new());
    let handles = apply_handles_without_tx_index(Network::Regtest, Arc::clone(&utxo));
    let genesis = Network::Regtest.genesis_block();
    let genesis_hash = Hash256::from(genesis.block_hash());
    let genesis_tip = applied_header_tip(&handles, genesis_hash, &genesis, 0)?;
    handles.applied_tip.store(Some(Arc::new(genesis_tip)));

    let block = mined_block_with_prev_hash_and_transactions(
        genesis.block_hash(),
        vec![coinbase_transaction(1)],
    )?;
    let raw = bytes::Bytes::from(consensus_bytes(&block));
    handles.apply_block(&block)?;

    handles.admission.close_permanently();

    let child = mined_block_with_prev_hash_and_transactions(
        block.block_hash(),
        vec![coinbase_transaction(2)],
    )?;
    assert!(
        matches!(handles.apply_block(&child), Err(ApplyError::Shutdown)),
        "connect must refuse after a tear"
    );
    assert!(
        matches!(
            handles.apply_window(&[&child], core::slice::from_ref(&raw)),
            Err(WindowApplyError {
                source: ApplyError::Shutdown,
                disposition: WindowApplyDisposition::Operational,
                ..
            })
        ),
        "the window path must refuse after a tear"
    );
    let disconnected = handles
        .disconnect_block(&block)
        .map(|outcome| outcome.parent_tip);
    assert!(
        matches!(
            disconnected,
            Err(crate::DisconnectError::Refused(ref boxed))
                if matches!(**boxed, ApplyError::Shutdown)
        ),
        "disconnect must refuse after a tear, got {disconnected:?}"
    );
    assert_eq!(
        handles.applied_tip.load_full().map(|tip| tip.height),
        Some(1),
        "the applied tip must not have moved while admission was closed"
    );
    Ok(())
}

#[test]
fn a_writer_waiting_on_chain_transition_rechecks_fatal_admission_before_mutating()
-> Result<(), Box<dyn std::error::Error>> {
    let utxo = Arc::new(UtxoSet::new());
    let handles = apply_handles_without_tx_index(Network::Regtest, Arc::clone(&utxo));
    let genesis = Network::Regtest.genesis_block();
    let genesis_hash = Hash256::from(genesis.block_hash());
    let genesis_tip = applied_header_tip(&handles, genesis_hash, &genesis, 0)?;
    handles.applied_tip.store(Some(Arc::new(genesis_tip)));
    let child = mined_block_with_prev_hash_and_transactions(
        genesis.block_hash(),
        vec![coinbase_transaction(1)],
    )?;
    let applied_before = handles
        .applied_tip
        .load_full()
        .ok_or_else(|| std::io::Error::other("missing applied tip"))?;
    let tree_tip_before = handles
        .block_tree
        .read()
        .tip()
        .map(|tip| (tip.tip_id, tip.height, tip.hash));
    let utxo_len_before = utxo.len();

    let transition = handles.chain_transition.lock();
    let (started_tx, started_rx) = std::sync::mpsc::sync_channel(0);
    let (shutdown, outcome_debug, admission_observed) = std::thread::scope(|scope| {
        let writer = scope.spawn(|| {
            if started_tx.send(()).is_err() {
                return (
                    false,
                    "parent stopped before apply worker started".to_owned(),
                );
            }
            let outcome = handles.apply_block(&child).map(|outcome| outcome.tip);
            (
                matches!(&outcome, Err(ApplyError::Shutdown)),
                format!("{outcome:?}"),
            )
        });

        started_rx
            .recv()
            .map_err(|_| std::io::Error::other("writer did not start apply_block"))?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut admission_observed = false;
        while std::time::Instant::now() < deadline {
            if handles.admission.barrier.is_locked() {
                admission_observed = true;
                break;
            }
            std::thread::yield_now();
        }

        handles.admission.close_permanently();
        drop(transition);
        let (shutdown, outcome_debug) = writer
            .join()
            .map_err(|_| std::io::Error::other("writer thread panicked"))?;
        Ok::<_, std::io::Error>((shutdown, outcome_debug, admission_observed))
    })?;

    assert!(
        admission_observed,
        "the public apply path never acquired its admission permit"
    );
    assert!(
        shutdown,
        "writer must recheck fatal closure after acquiring chain_transition, got {outcome_debug}"
    );
    assert_eq!(
        handles
            .applied_tip
            .load_full()
            .map(|tip| (tip.tip_id, tip.height, tip.hash)),
        Some((
            applied_before.tip_id,
            applied_before.height,
            applied_before.hash
        )),
        "the waiting writer must not publish a new applied tip"
    );
    assert_eq!(
        handles
            .block_tree
            .read()
            .tip()
            .map(|tip| (tip.tip_id, tip.height, tip.hash)),
        tree_tip_before,
        "the waiting writer must not mutate the active header index"
    );
    assert_eq!(
        utxo.len(),
        utxo_len_before,
        "the waiting writer must not mutate UTXOs"
    );
    Ok(())
}

/// Authoritative applied-tip moves must reach the template coordinator's
/// long-poll waiters through the shared `MiningGenerationSignal`: one
/// wake per connect and one per disconnect, fired after the tip is
/// published.
#[test]
fn connect_and_disconnect_wake_the_mining_generation() -> Result<(), Box<dyn std::error::Error>> {
    let genesis = Network::Regtest.genesis_block();
    let utxo = Arc::new(UtxoSet::new());
    let handles = apply_handles_without_tx_index(Network::Regtest, Arc::clone(&utxo));
    let control = Arc::new(RecordingGenerationControl {
        published: Mutex::new(0),
    });
    let control_dyn: Arc<dyn bitcoin_rs_mining::MiningControl> = control.clone();
    let mining = Arc::new(crate::mining::MiningGenerationSignal::new());
    mining.attach(&control_dyn);
    let followers = crate::chain_effects::ChainFollowers::new(
        crate::chain_effects::ChainEffects::noop(),
        mining,
        None,
    );
    assert_eq!(*control.published.lock(), 0, "nothing ran yet");

    let genesis_hash = Hash256::from(genesis.block_hash());
    let genesis_tip = applied_header_tip(&handles, genesis_hash, &genesis, 0)?;
    handles.applied_tip.store(Some(Arc::new(genesis_tip)));

    let block = mined_block_with_prev_hash_and_transactions(
        genesis.block_hash(),
        vec![coinbase_transaction(1)],
    )?;
    apply_followed(&handles, &followers, &block)?;
    assert_eq!(
        *control.published.lock(),
        1,
        "the connect's tip publication must wake the coordinator once"
    );

    disconnect_followed(&handles, &followers, &block)?;
    assert_eq!(
        *control.published.lock(),
        2,
        "the disconnect's tip publication must wake the coordinator once"
    );
    Ok(())
}

#[test]
fn permanent_window_failure_invalidates_failed_subtree_and_descendants()
-> Result<(), Box<dyn std::error::Error>> {
    let handles = empty_apply_handles_for_network(Network::Regtest);
    let genesis = Network::Regtest.genesis_block();
    let genesis_tip = applied_header_tip(&handles, genesis.block_hash().0, &genesis, 0)?;
    handles.applied_tip.store(Some(Arc::new(genesis_tip)));
    let applied = mined_block_with_prev_hash_and_transactions(
        genesis.block_hash(),
        vec![coinbase_transaction(1)],
    )?;
    handles.apply_block(&applied)?;
    let applied_hash = applied.block_hash().0;

    let bad = mined_block_with_prev_hash_and_transactions(
        applied.block_hash(),
        vec![coinbase_transaction(2)],
    )?;
    // Corrupt the body against its own header: the txid changes, so the
    // header merkle root no longer matches and block rules reject the
    // block with a permanent consensus error before any write.
    let mut bad_body = bad.clone();
    bad_body.txs[0].outputs[0].value = Amount::from_sat(2);
    let descendant = mined_block_with_prev_hash_and_transactions(
        bad.block_hash(),
        vec![coinbase_transaction(3)],
    )?;
    {
        let mut tree = handles.block_tree.write();
        tree.insert_header(bad.header, NodeStatus::HeaderValid)?;
        tree.insert_header(descendant.header, NodeStatus::HeaderValid)?;
    }
    let bad_hash = bad.block_hash().0;
    let descendant_hash = descendant.block_hash().0;
    let raw = bytes::Bytes::from(consensus_bytes(&bad_body));

    let outcome = handles
        .apply_window(&[&bad_body], core::slice::from_ref(&raw))
        .map(|_| ());
    let Err(error) = outcome else {
        panic!("a body contradicting its header merkle root must fail");
    };
    assert_eq!(error.disposition(), WindowApplyDisposition::Permanent);
    assert_eq!(
        error.invalidated(),
        &[bad_hash, descendant_hash],
        "the failed block and every descendant are invalid, in slab order"
    );
    {
        let tree = handles.block_tree.read();
        assert_eq!(
            tree.node_by_hash(bad_hash).map(|node| node.status),
            Some(NodeStatus::Invalid)
        );
        assert_eq!(
            tree.node_by_hash(descendant_hash).map(|node| node.status),
            Some(NodeStatus::Invalid)
        );
    }
    assert_eq!(
        handles.applied_tip.load_full().map(|tip| tip.hash),
        Some(applied_hash),
        "invalidation republishes the valid prefix, never the failed block"
    );
    assert_eq!(handles.utxo.len(), 1, "the failed block committed nothing");
    Ok(())
}

#[test]
fn operational_window_failure_keeps_failed_block_retryable()
-> Result<(), Box<dyn std::error::Error>> {
    let mut handles = empty_apply_handles_for_network(Network::Regtest);
    let genesis = Network::Regtest.genesis_block();
    let genesis_tip = applied_header_tip(&handles, genesis.block_hash().0, &genesis, 0)?;
    handles.applied_tip.store(Some(Arc::new(genesis_tip)));
    let applied = mined_block_with_prev_hash_and_transactions(
        genesis.block_hash(),
        vec![coinbase_transaction(1)],
    )?;
    handles.apply_block(&applied)?;
    let applied_hash = applied.block_hash().0;
    // The block's header was never accepted by header sync, so tree
    // preparation would have to insert it; the block stays unseen unless
    // apply gets that far.
    let bad = mined_block_with_prev_hash_and_transactions(
        applied.block_hash(),
        vec![coinbase_transaction(2)],
    )?;
    let bad_hash = bad.block_hash().0;
    // The persisted-undo write fails: an operational error.
    handles.undo_store = Arc::new(FailingUndoPersist {
        inner: InMemoryUndoStore::default(),
    });
    let raw = bytes::Bytes::from(consensus_bytes(&bad));

    let outcome = handles
        .apply_window(&[&bad], core::slice::from_ref(&raw))
        .map(|_| ());
    let Err(error) = outcome else {
        panic!("an undo-persist failure must fail the window");
    };
    assert_eq!(error.disposition(), WindowApplyDisposition::Operational);
    assert!(
        error.invalidated().is_empty(),
        "operational failures must not mark the block or its subtree invalid"
    );
    {
        let tree = handles.block_tree.read();
        assert!(
            tree.node_by_hash(bad_hash).is_none(),
            "tree preparation runs before the failing persist and must leave no node behind"
        );
    }
    assert_eq!(
        handles.applied_tip.load_full().map(|tip| tip.hash),
        Some(applied_hash),
        "the failed block must not move the applied tip"
    );
    assert_eq!(
        handles.utxo.len(),
        1,
        "the failed block must not commit outputs"
    );
    Ok(())
}
