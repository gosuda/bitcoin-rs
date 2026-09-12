use super::*;

#[test]
#[allow(clippy::arc_with_non_send_sync)]
fn txindex_worker_failure_makes_queries_unavailable_without_blocking_apply()
-> Result<(), Box<dyn std::error::Error>> {
    let handles = apply_handles_without_tx_index(Network::Regtest, Arc::new(UtxoSet::new()));
    let (wake_tx, wake_rx) = crossbeam_channel::bounded(1);
    let runtime = Arc::new(crate::txindex::DerivedIndexRuntime::new(wake_tx));
    let index: Arc<FailAfterStartupTxIndex> = Arc::new(FailAfterStartupTxIndex::new()?);
    let writer: Arc<dyn bitcoin_rs_index::writer::TxIndexWriter> = index.clone();
    let evidence_dir = tempfile::tempdir()?;
    let _worker = crate::txindex::DerivedIndexWorker::spawn(
        Arc::clone(&runtime),
        writer,
        Arc::clone(&handles.applied_tip),
        Arc::clone(&handles.block_tree),
        None,
        crate::txindex::DEFAULT_BATCH_LIMITS,
        bitcoin_rs_index::IndexCapabilities::HISTORICAL,
        Arc::new(crate::state::ChainEventPublisher::detached(0).0),
        crate::txindex::test_recovery_reporter(evidence_dir.path()).0,
        u32::MAX,
        wake_rx,
    )?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    assert!(
        wait_until(deadline, || {
            index
                .fenced_calls
                .load(std::sync::atomic::Ordering::Acquire)
                >= 2
        }),
        "txindex worker did not complete its startup reconciliation"
    );

    let genesis = Network::Regtest.genesis_block();
    let genesis_hash = Hash256::from(genesis.block_hash());
    let genesis_tip = applied_header_tip(&handles, genesis_hash, &genesis, 0)?;
    handles.applied_tip.store(Some(Arc::new(genesis_tip)));
    index.fail.store(true, std::sync::atomic::Ordering::Release);
    runtime.wake();

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    assert!(
        wait_until(deadline, || runtime.failure_message().is_some()),
        "supervised txindex worker did not publish its writer failure"
    );
    assert!(
        runtime
            .failure_message()
            .is_some_and(|message| message.contains("does not support block disconnect")),
        "worker must publish the failing writer's error"
    );

    let reader: Arc<dyn bitcoin_rs_index::IndexReader> = index;
    let query = crate::txindex::DerivedIndexQueryEngine::new(
        Arc::clone(&runtime),
        reader,
        crate::txindex::IndexBlockSource::new(Arc::new(parking_lot::RwLock::new(
            bitcoin_rs_rpc::context::BlockLog::new(),
        ))),
        Arc::clone(&handles.block_tree),
        Arc::clone(&handles.applied_tip),
        None,
        crate::txindex::QueryEngineLive {
            utxo: None,
            chain_transition: None,
            enabled: bitcoin_rs_index::IndexCapabilities::TX_LOOKUP,
        },
    );
    let query_result =
        bitcoin_rs_rpc::context::DerivedIndexQuery::transaction(&query, &genesis.txs[0].txid());
    assert!(
        matches!(
            query_result,
            Err(bitcoin_rs_rpc::context::TxQueryError::Unavailable(_))
        ),
        "failed txindex queries must be explicitly unavailable, got {query_result:?}"
    );

    let block = mined_block_with_prev_hash_and_transactions(
        genesis.block_hash(),
        vec![coinbase_transaction(1)],
    )?;
    let expected_hash = Hash256::from(block.block_hash());
    let applied = handles.apply_block(&block)?.tip;
    assert_eq!(applied.height, 1);
    assert_eq!(applied.hash, expected_hash);
    assert_eq!(
        handles
            .applied_tip
            .load_full()
            .as_ref()
            .map(|tip| (tip.height, tip.hash)),
        Some((1, expected_hash)),
        "authoritative block application must commit after txindex failure"
    );

    Ok(())
}

#[test]
fn invalidate_block_rejects_unknown_and_genesis_without_mutation()
-> Result<(), Box<dyn std::error::Error>> {
    let handles = apply_handles_without_tx_index(Network::Regtest, Arc::new(UtxoSet::new()));
    let genesis = Network::Regtest.genesis_block();
    let genesis_hash = Hash256::from(genesis.block_hash());
    let genesis_tip = applied_header_tip(&handles, genesis_hash, &genesis, 0)?;
    handles
        .applied_tip
        .store(Some(Arc::new(genesis_tip.clone())));
    let header_tip_before = handles.chain_tip.load_full();

    let unknown = Hash256::from_le_bytes(&[0x5a; 32]);
    assert!(matches!(
        crate::reorg::invalidate_block(&handles, &crate::chain_effects::ChainFollowers::noop(), unknown),
        Err(crate::reorg::ReorgError::UnknownBlock(hash)) if hash == unknown
    ));
    assert!(matches!(
        crate::reorg::invalidate_block(
            &handles,
            &crate::chain_effects::ChainFollowers::noop(),
            genesis_hash
        ),
        Err(crate::reorg::ReorgError::CannotInvalidateGenesis)
    ));
    assert_eq!(handles.chain_tip.load_full(), header_tip_before);
    assert_eq!(
        handles.applied_tip.load_full().as_deref(),
        Some(&genesis_tip)
    );
    assert_eq!(
        handles.block_tree.read().node(genesis_tip.tip_id)?.status,
        NodeStatus::Active
    );
    Ok(())
}

/// `Fatal` is what keeps a torn chainstate from being retried, and the
/// reason it stays unreachable is that `plan_disconnect` checks the
/// coinstats height before anything mutates. Drop that check and the same
/// desync lands mid-rollback instead: the UTXO undo commits, the coinstats
/// rewind rejects the height, and the node is torn.
///
/// So this pins the precheck, not the tear. A desync must refuse with
/// nothing touched — same applied tip, same coins.
#[test]
fn a_coinstats_desync_refuses_before_it_can_tear_anything() -> Result<(), Box<dyn std::error::Error>>
{
    let ReorgBodyLoadingFixture {
        handles,
        utxo,
        target,
        losing,
        applied,
        ..
    } = reorg_body_loading_fixture()?;

    // Inject only the stats height mismatch. The disconnect precheck must
    // catch it before committing any UTXO undo.
    handles.coin_stats.finish_block(999, 0);

    let outcome = crate::reorg::switch_to_branch(
        &handles,
        &crate::chain_effects::ChainFollowers::noop(),
        target,
        |_| None,
        |_| {},
    );
    assert!(
        matches!(outcome, Err(crate::reorg::ReorgError::Refused { .. })),
        "the precheck must refuse rather than tear, got {outcome:?}"
    );
    assert_eq!(
        handles.applied_tip.load_full().map(|tip| tip.hash),
        Some(applied.hash),
        "a refused disconnect must leave the applied tip alone"
    );
    assert!(
        utxo.has_live_outputs_for_txid(&Hash256::from(losing.txs[0].txid())),
        "a refused disconnect must not have undone any coins"
    );
    // MPL-04: a refused disconnect leaves the original committed tip
    // coherent and must release the generation before another attempt.
    assert!(
        handles.mempool_gateway.stable_generation().is_some(),
        "a clean disconnect refusal must reopen admission"
    );
    handles.coin_stats.finish_block(applied.height, 0);
    crate::reorg::switch_to_branch(
        &handles,
        &crate::chain_effects::ChainFollowers::noop(),
        target,
        |_| None,
        |_| {},
    )?;
    assert_eq!(
        handles.applied_tip.load_full().map(|tip| tip.tip_id),
        Some(target),
        "repairing the injected stats mismatch must permit the same reorg"
    );
    assert!(!utxo.has_live_outputs_for_txid(&Hash256::from(losing.txs[0].txid())));
    assert!(handles.mempool_gateway.stable_generation().is_some());
    Ok(())
}
