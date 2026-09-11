use super::*;

/// A block that is not the applied tip must be refused before the UTXO set
/// is mutated. Disconnecting from the middle would restore outputs that
/// descendants have already spent, and the tip would move to a state the
/// UTXO set does not describe.
#[test]
#[allow(clippy::arc_with_non_send_sync)]
fn disconnect_refuses_a_block_that_is_not_the_applied_tip() -> Result<(), Box<dyn std::error::Error>>
{
    let genesis = Network::Regtest.genesis_block();
    let utxo = Arc::new(UtxoSet::new());
    let handles = apply_handles_without_tx_index(Network::Regtest, Arc::clone(&utxo));
    let genesis_hash = Hash256::from(genesis.block_hash());
    let genesis_tip = applied_header_tip(&handles, genesis_hash, &genesis, 0)?;
    handles.applied_tip.store(Some(Arc::new(genesis_tip)));

    let block_1 = mined_block_with_prev_hash_and_transactions(
        genesis.block_hash(),
        vec![coinbase_transaction(1)],
    )?;
    handles.apply_block(&block_1)?;
    let block_2 = mined_block_with_prev_hash_and_transactions(
        block_1.block_hash(),
        vec![coinbase_transaction(2)],
    )?;
    handles.apply_block(&block_2)?;
    let outputs_before = utxo.len();

    let outcome = handles
        .disconnect_block(&block_1)
        .map(|outcome| outcome.parent_tip);

    assert!(
        matches!(
            &outcome,
            Err(crate::DisconnectError::Refused(boxed))
                if matches!(**boxed, ApplyError::DisconnectNotTip { .. })
        ),
        "disconnecting a non-tip block must be refused, got {outcome:?}"
    );
    assert_eq!(
        utxo.len(),
        outputs_before,
        "a refused disconnect must not touch the UTXO set"
    );
    assert_eq!(
        handles
            .applied_tip
            .load()
            .as_ref()
            .map_or(0, |tip| tip.height),
        2,
        "a refused disconnect must leave the tip where it was"
    );
    Ok(())
}

/// Without the record the prior UTXO state is unknowable. Proceeding would
/// silently corrupt the set, so the disconnect must fail and change nothing.
#[test]
#[allow(clippy::arc_with_non_send_sync)]
fn disconnect_refuses_when_the_undo_record_is_absent() -> Result<(), Box<dyn std::error::Error>> {
    let genesis = Network::Regtest.genesis_block();
    let utxo = Arc::new(UtxoSet::new());
    let mut handles = apply_handles_without_tx_index(Network::Regtest, Arc::clone(&utxo));
    let genesis_hash = Hash256::from(genesis.block_hash());
    let genesis_tip = applied_header_tip(&handles, genesis_hash, &genesis, 0)?;
    handles.applied_tip.store(Some(Arc::new(genesis_tip)));

    let block = mined_block_with_prev_hash_and_transactions(
        genesis.block_hash(),
        vec![coinbase_transaction(1)],
    )?;
    handles.apply_block(&block)?;
    let outputs_before = utxo.len();

    // Swap in an empty store, standing in for a record lost to pruning.
    handles.undo_store = Arc::new(InMemoryUndoStore::default());
    let outcome = handles
        .disconnect_block(&block)
        .map(|outcome| outcome.parent_tip);

    assert!(
        matches!(
            &outcome,
            Err(crate::DisconnectError::Refused(boxed))
                if matches!(**boxed, ApplyError::UndoRecordMissing { .. })
        ),
        "a missing undo record must refuse the disconnect, got {outcome:?}"
    );
    assert_eq!(
        utxo.len(),
        outputs_before,
        "a refused disconnect must not touch the UTXO set"
    );
    assert_eq!(
        handles
            .applied_tip
            .load()
            .as_ref()
            .map_or(0, |tip| tip.height),
        1,
        "a refused disconnect must leave the tip where it was"
    );
    Ok(())
}

/// The rewind is wired to the disconnect, not merely implemented.
///
/// `rewind_chain_tx_count` has its own unit tests, and they all passed while
/// the call site was missing: a mutation that deleted the call from
/// `disconnect_block_admitted` survived the whole audit. Testing a function
/// is not testing that anything calls it.
#[test]
fn a_disconnect_takes_the_blocks_transactions_back_out_of_the_chain_count()
-> Result<(), Box<dyn std::error::Error>> {
    let genesis = Network::Regtest.genesis_block();
    let utxo = Arc::new(UtxoSet::new());
    let handles = apply_handles_without_tx_index(Network::Regtest, Arc::clone(&utxo));
    let genesis_hash = Hash256::from(genesis.block_hash());
    let genesis_tip = applied_header_tip(&handles, genesis_hash, &genesis, 0)?;
    handles.applied_tip.store(Some(Arc::new(genesis_tip)));
    // Genesis counted, as it would be on a node that synced from it.
    handles.chain_tx_count.store(1, Ordering::Relaxed);

    let block = mined_block_with_prev_hash_and_transactions(
        genesis.block_hash(),
        vec![coinbase_transaction(1)],
    )?;
    let applied = handles.apply_block(&block)?.tip;
    assert_eq!(applied.height, 1, "the block must connect first");
    assert_eq!(
        handles.chain_tx_count.load(Ordering::Relaxed),
        2,
        "connecting a one-transaction block moves the count by one"
    );
    assert_eq!(
        handles
            .block_tree
            .read()
            .node(applied.tip_id)?
            .chain_tx_count,
        2,
        "apply must record the per-node count the RPC reads"
    );

    let _restored = handles.disconnect_block(&block)?.parent_tip;
    assert_eq!(
        handles.chain_tx_count.load(Ordering::Relaxed),
        1,
        "the disconnected block's transactions must leave the count with it"
    );
    Ok(())
}

#[test]
fn a_branch_with_unavailable_bodies_moves_nothing() -> Result<(), Box<dyn std::error::Error>> {
    let utxo = Arc::new(UtxoSet::new());
    let mut handles = apply_handles_without_tx_index(Network::Regtest, Arc::clone(&utxo));
    let bodies = Arc::new(MapBodyStore::default());
    let body_arc = Arc::clone(&bodies);
    let body_handle: Arc<dyn bitcoin_rs_storage::block_body::BlockBodyStore> = body_arc;
    handles.block_body_store = Some(body_handle);

    let genesis = Network::Regtest.genesis_block();
    let genesis_hash = Hash256::from(genesis.block_hash());
    let genesis_tip = applied_header_tip(&handles, genesis_hash, &genesis, 0)?;
    handles.applied_tip.store(Some(Arc::new(genesis_tip)));

    let applied_block = mined_block_with_prev_hash_and_transactions(
        genesis.block_hash(),
        vec![coinbase_transaction(1)],
    )?;
    let raw = bytes::Bytes::from(consensus_bytes(&applied_block));
    let applied = handles
        .apply_block_with_serialized(&applied_block, raw.clone())?
        .tip;
    bodies
        .bodies
        .write()
        .insert((applied.height, applied.hash), raw.to_vec());

    // A competing branch whose headers are known and whose bodies are not.
    let rival_one = mined_block_with_prev_hash_and_transactions(
        genesis.block_hash(),
        vec![coinbase_transaction(2)],
    )?;
    let rival_two = mined_block_with_prev_hash_and_transactions(
        rival_one.block_hash(),
        vec![coinbase_transaction(3)],
    )?;
    let target = {
        let mut tree = handles.block_tree.write();
        let mut last = None;
        for block in [&rival_one, &rival_two] {
            last = Some(tree.insert_header(
                block.header,
                bitcoin_rs_chain::node::NodeStatus::HeaderValid,
            )?);
        }
        last.ok_or_else(|| anyhow::anyhow!("no rival branch built"))?
    };

    let outcome = crate::reorg::switch_to_branch(
        &handles,
        &crate::chain_effects::ChainFollowers::noop(),
        target,
        |_| None,
        |_| {},
    );
    assert!(
        matches!(outcome, Err(crate::reorg::ReorgError::MissingBody { .. })),
        "an unavailable branch must report a missing body, got {outcome:?}"
    );
    assert_eq!(
        handles.applied_tip.load_full().map(|tip| tip.hash),
        Some(applied.hash),
        "the applied tip must not move when the candidate branch is incomplete"
    );
    assert!(
        utxo.has_live_outputs_for_txid(&Hash256::from(applied_block.txs[0].txid())),
        "the applied branch's coins must survive an aborted switch"
    );
    Ok(())
}

#[test]
fn reorg_sequence_events_disconnect_old_tip_before_connecting_new_branch()
-> Result<(), Box<dyn std::error::Error>> {
    let utxo = Arc::new(UtxoSet::new());
    let publisher = Arc::new(RecordingSequencePublisher::default());
    let publisher_handle: Arc<dyn crate::ZmqPublisher> = publisher.clone();
    let followers = zmq_followers(publisher_handle);
    let mut handles = apply_handles_without_tx_index(Network::Regtest, Arc::clone(&utxo));
    let bodies = Arc::new(MapBodyStore::default());
    handles.block_body_store = Some(bodies.clone());

    let genesis = Network::Regtest.genesis_block();
    let genesis_hash = Hash256::from(genesis.block_hash());
    let genesis_tip = applied_header_tip(&handles, genesis_hash, &genesis, 0)?;
    handles.applied_tip.store(Some(Arc::new(genesis_tip)));

    let old_one = mined_block_with_prev_hash_and_transactions(
        genesis.block_hash(),
        vec![coinbase_transaction(1)],
    )?;
    let old_one_raw = bytes::Bytes::from(consensus_bytes(&old_one));
    let old_one_tip = handles
        .apply_block_with_serialized(&old_one, old_one_raw.clone())?
        .tip;
    bodies
        .bodies
        .write()
        .insert((old_one_tip.height, old_one_tip.hash), old_one_raw.to_vec());

    let old_two = mined_block_with_prev_hash_and_transactions(
        old_one.block_hash(),
        vec![coinbase_transaction(2)],
    )?;
    let old_two_raw = bytes::Bytes::from(consensus_bytes(&old_two));
    let old_two_tip = handles
        .apply_block_with_serialized(&old_two, old_two_raw.clone())?
        .tip;
    bodies
        .bodies
        .write()
        .insert((old_two_tip.height, old_two_tip.hash), old_two_raw.to_vec());
    publisher.events.lock().clear();
    *publisher.next_sequence.lock() = 0;

    let new_one = mined_block_with_prev_hash_and_transactions(
        genesis.block_hash(),
        vec![coinbase_transaction(3)],
    )?;
    let new_two = mined_block_with_prev_hash_and_transactions(
        new_one.block_hash(),
        vec![coinbase_transaction(4)],
    )?;
    let target = {
        let mut tree = handles.block_tree.write();
        let mut target = None;
        for (height, block) in [(1_u32, &new_one), (2_u32, &new_two)] {
            target = Some(tree.insert_header(block.header, NodeStatus::HeaderValid)?);
            bodies.bodies.write().insert(
                (height, Hash256::from(block.block_hash())),
                consensus_bytes(block),
            );
        }
        target.ok_or_else(|| anyhow::anyhow!("new branch has no target"))?
    };

    crate::reorg::switch_to_branch(&handles, &followers, target, |_| None, |_| {})?;

    let events = publisher.events.lock().clone();
    assert_eq!(
        events,
        vec![
            (Hash256::from(old_two.block_hash()), b'D', 0),
            (Hash256::from(old_one.block_hash()), b'D', 1),
            (Hash256::from(new_one.block_hash()), b'C', 2),
            (Hash256::from(new_two.block_hash()), b'C', 3),
        ]
    );
    Ok(())
}

#[test]
fn invalidate_block_disconnects_active_tip_and_emits_sequence_event()
-> Result<(), Box<dyn std::error::Error>> {
    let utxo = Arc::new(UtxoSet::new());
    let publisher = Arc::new(RecordingSequencePublisher::default());
    let publisher_handle: Arc<dyn crate::ZmqPublisher> = publisher.clone();
    let followers = zmq_followers(publisher_handle);
    let mut handles = apply_handles_without_tx_index(Network::Regtest, Arc::clone(&utxo));
    let bodies = Arc::new(MapBodyStore::default());
    handles.block_body_store = Some(bodies.clone());

    let genesis = Network::Regtest.genesis_block();
    let genesis_hash = Hash256::from(genesis.block_hash());
    let genesis_tip = applied_header_tip(&handles, genesis_hash, &genesis, 0)?;
    handles.applied_tip.store(Some(Arc::new(genesis_tip)));

    let one = mined_block_with_prev_hash_and_transactions(
        genesis.block_hash(),
        vec![coinbase_transaction(1)],
    )?;
    let one_raw = bytes::Bytes::from(consensus_bytes(&one));
    let one_tip = handles
        .apply_block_with_serialized(&one, one_raw.clone())?
        .tip;
    bodies
        .bodies
        .write()
        .insert((one_tip.height, one_tip.hash), one_raw.to_vec());

    let two = mined_block_with_prev_hash_and_transactions(
        one.block_hash(),
        vec![coinbase_transaction(2)],
    )?;
    let two_raw = bytes::Bytes::from(consensus_bytes(&two));
    let two_tip = handles
        .apply_block_with_serialized(&two, two_raw.clone())?
        .tip;
    bodies
        .bodies
        .write()
        .insert((two_tip.height, two_tip.hash), two_raw.to_vec());
    publisher.events.lock().clear();
    *publisher.next_sequence.lock() = 0;

    crate::reorg::invalidate_block(&handles, &followers, two_tip.hash)?;

    assert_eq!(
        handles.applied_tip.load_full().map(|tip| tip.hash),
        Some(one_tip.hash)
    );
    let tree = handles.block_tree.read();
    let invalid_id = tree.lookup(two_tip.hash).ok_or("missing invalidated tip")?;
    assert_eq!(tree.node(invalid_id)?.status, NodeStatus::Invalid);
    drop(tree);
    assert_eq!(
        publisher.events.lock().as_slice(),
        &[(two_tip.hash, b'D', 0)]
    );
    Ok(())
}

#[test]
fn invalidate_block_missing_disconnect_body_mutates_nothing()
-> Result<(), Box<dyn std::error::Error>> {
    let utxo = Arc::new(UtxoSet::new());
    let mut handles = apply_handles_without_tx_index(Network::Regtest, Arc::clone(&utxo));
    let bodies = Arc::new(MapBodyStore::default());
    handles.block_body_store = Some(bodies.clone());

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
    bodies
        .bodies
        .write()
        .remove(&(applied.height, applied.hash));

    let header_tip_before = handles.chain_tip.load_full();
    let applied_tip_before = handles.applied_tip.load_full();
    let utxo_len_before = utxo.len();
    let outcome = crate::reorg::invalidate_block(
        &handles,
        &crate::chain_effects::ChainFollowers::noop(),
        applied.hash,
    );

    assert!(
        matches!(outcome, Err(crate::reorg::ReorgError::MissingBody { .. })),
        "missing disconnect data must abort invalidation, got {outcome:?}"
    );
    assert_eq!(
        handles.block_tree.read().node(applied.tip_id)?.status,
        NodeStatus::Active,
        "preflight failure must leave the requested header valid and active"
    );
    assert_eq!(handles.chain_tip.load_full(), header_tip_before);
    assert_eq!(handles.applied_tip.load_full(), applied_tip_before);
    assert_eq!(utxo.len(), utxo_len_before);
    // MPL-04: a read-only preflight refusal must release its generation.
    assert!(
        handles.mempool_gateway.stable_generation().is_some(),
        "missing disconnect data must not leave admission closed"
    );

    bodies
        .bodies
        .write()
        .insert((applied.height, applied.hash), raw.to_vec());
    crate::reorg::invalidate_block(
        &handles,
        &crate::chain_effects::ChainFollowers::noop(),
        applied.hash,
    )?;
    assert_eq!(
        handles.applied_tip.load_full().map(|tip| tip.hash),
        Some(genesis_hash),
        "restoring the body must allow invalidation without restarting"
    );
    assert_eq!(
        handles.block_tree.read().node(applied.tip_id)?.status,
        NodeStatus::Invalid
    );
    assert!(handles.mempool_gateway.stable_generation().is_some());
    Ok(())
}
