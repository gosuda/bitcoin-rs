use super::*;

#[test]
fn block_apply_predecessor_uses_applied_tip_when_header_tip_is_ahead()
-> Result<(), Box<dyn std::error::Error>> {
    let handles = empty_apply_handles_for_network(Network::Regtest);
    let mut tree = handles.block_tree.write();
    let genesis = Network::Regtest.genesis_block();
    let genesis_id = tree.insert_node(None, genesis.header, NodeStatus::HeaderValid)?;
    let genesis_node = tree.node(genesis_id)?;
    let genesis_tip = TipSnapshot {
        tip_id: genesis_id,
        height: genesis_node.height,
        chainwork: genesis_node.chainwork,
        hash: genesis_node.hash,
    };
    let mut tip_id = genesis_id;
    for height in 1..=3 {
        let parent_hash = BlockHash::from(tree.node(tip_id)?.hash);
        let header = pow_header(parent_hash, 0x207f_ffff, height, height);
        tip_id = tree.insert_node(Some(tip_id), header, NodeStatus::HeaderValid)?;
    }
    handles.chain_tip.store(tree.tip());
    drop(tree);
    handles
        .applied_tip
        .store(Some(Arc::new(genesis_tip.clone())));

    let (prior, height) = applied_predecessor(
        &handles,
        Hash256::from_le_bytes(&[0x42; 32]),
        genesis_tip.hash,
    )?;

    let prior = prior.ok_or_else(|| std::io::Error::other("missing predecessor"))?;
    assert_eq!(prior.tip_id, genesis_id);
    assert_eq!(height, 1);
    Ok(())
}

#[test]
fn block_apply_predecessor_rejects_non_genesis_without_applied_tip() {
    let handles = empty_apply_handles_for_network(Network::Regtest);
    let prev_hash = Hash256::from_le_bytes(&[0x11; 32]);
    let error = match applied_predecessor(&handles, Hash256::from_le_bytes(&[0x22; 32]), prev_hash)
    {
        Ok(_) => panic!("non-genesis block must not start the applied chain"),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        ApplyError::Chain(bitcoin_rs_chain::ChainError::MissingParent { prev_hash: got }) if got == prev_hash
    ));
}

#[test]
fn applied_header_tip_reuses_preaccepted_header() -> Result<(), Box<dyn std::error::Error>> {
    let handles = empty_apply_handles_for_network(Network::Regtest);
    let block = Network::Regtest.genesis_block();
    let block_hash = Hash256::from(block.block_hash());
    let header_id = handles
        .block_tree
        .write()
        .insert_header(block.header, NodeStatus::HeaderValid)?;

    let tip = applied_header_tip(&handles, block_hash, &block, 0)?;

    assert_eq!(tip.tip_id, header_id);
    assert_eq!(tip.height, 0);
    assert_eq!(tip.hash, block_hash);
    Ok(())
}

#[test]
fn testnet4_retarget_uses_first_period_bits_after_min_difficulty_tip()
-> Result<(), Box<dyn std::error::Error>> {
    let handles = empty_apply_handles_for_network(Network::Testnet4);
    let interval = handles.network.retarget_interval();
    let expected_timespan = interval * 600;
    let first_period_bits = scaled_pow_limit_bits(&handles, 16);
    let pow_limit_bits = pow_limit_bits(&handles);
    let parent_hash = seed_pow_period_with_tip_bits(
        &handles,
        first_period_bits,
        pow_limit_bits,
        DAA_ANCHOR_TIME,
        DAA_ANCHOR_TIME + expected_timespan,
        interval - 1,
    )?;
    let block = block_with_pow_header(
        parent_hash,
        first_period_bits,
        DAA_ANCHOR_TIME + expected_timespan + 600,
        interval,
    );

    assert!(check_pow_limit_and_continuity_for_seeded_tip(&handles, &block, interval).is_ok());
    Ok(())
}

/// The window's two caps, and which one binds.
///
/// Count alone is wrong at the tip and bytes alone is wrong at genesis, so
/// the rule is whichever binds first. The oversized-block case is the one
/// worth pinning: a block bigger than the whole byte cap must still go
/// through, or the chain stalls on it.
#[test]
fn a_window_stops_at_whichever_cap_binds_first() {
    // Tiny blocks: the count cap binds.
    assert_eq!(
        window_len(std::iter::repeat_n(256, SCRIPT_BATCH_WINDOW * 2)),
        SCRIPT_BATCH_WINDOW,
        "small blocks must fill the window to its count cap"
    );

    // Tip-sized blocks: the byte cap binds long before the count does.
    let tip_block = 2 << 20;
    let expected = SCRIPT_BATCH_MAX_BYTES / tip_block;
    assert_eq!(
        window_len(std::iter::repeat_n(tip_block, SCRIPT_BATCH_WINDOW)),
        expected,
        "tip-sized blocks must be cut off by the byte cap"
    );
    assert!(
        expected < SCRIPT_BATCH_WINDOW,
        "this assertion is vacuous unless the byte cap binds first here"
    );

    // A single block larger than the entire byte cap still goes through.
    assert_eq!(
        window_len([SCRIPT_BATCH_MAX_BYTES * 2, 256]),
        1,
        "an oversized block must be applied alone, not refused"
    );

    assert_eq!(window_len([]), 0, "an empty window is empty");
}

/// A marker-completion failure poisons the node after the applied tip has
/// already moved. Derived consumers are not dispatched on that error: the
/// caller got `MarkerStuck`, not a committed outcome.
#[test]
fn disconnect_marker_stuck_leaves_the_tip_rolled_back() -> Result<(), Box<dyn std::error::Error>> {
    let genesis = Network::Regtest.genesis_block();
    let mut handles = apply_handles_without_tx_index(Network::Regtest, Arc::new(UtxoSet::new()));
    handles.undo_store = Arc::new(CompleteRejectingUndoStore::default());
    let genesis_tip =
        applied_header_tip(&handles, Hash256::from(genesis.block_hash()), &genesis, 0)?;
    handles.applied_tip.store(Some(Arc::new(genesis_tip)));

    let block = mined_block_with_prev_hash_and_transactions(
        genesis.block_hash(),
        vec![coinbase_transaction(6)],
    )?;
    handles.apply_block(&block)?;

    let outcome = handles.disconnect_block(&block);
    assert!(
        matches!(outcome, Err(crate::DisconnectError::MarkerStuck { .. })),
        "marker completion failure must report MarkerStuck, got {outcome:?}"
    );
    assert_eq!(
        handles
            .applied_tip
            .load_full()
            .as_deref()
            .map(|tip| tip.height),
        Some(0),
        "the applied tip must already be rolled back on MarkerStuck"
    );
    Ok(())
}

/// The round trip that makes the node a full node: connect a block, then
/// disconnect it and land on exactly the state that preceded it. A spend is
/// included deliberately, because a coinbase-only block would exercise only
/// the removes half and leave the restores half unproven.
#[test]
#[allow(clippy::arc_with_non_send_sync)]
fn disconnecting_the_tip_restores_the_exact_prior_state() -> Result<(), Box<dyn std::error::Error>>
{
    let genesis = Network::Regtest.genesis_block();
    let utxo = Arc::new(UtxoSet::new());
    // No transaction index runtime: the index has its own rollback tests in
    // `crates/index`. This isolates the UTXO and tip halves from any
    // asynchronous index work.
    let handles = apply_handles_without_tx_index(Network::Regtest, Arc::clone(&utxo));
    let genesis_hash = Hash256::from(genesis.block_hash());
    let genesis_tip = applied_header_tip(&handles, genesis_hash, &genesis, 0)?;
    handles.applied_tip.store(Some(Arc::new(genesis_tip)));

    // A mature output for the block to spend, so the undo record carries a
    // restore as well as a remove.
    let funding_txid = fixture_txid(0x8b);
    let funded = OutPoint::new(funding_txid, 0);
    let funded_value = 50_000;
    let mut seed = bitcoin_rs_utxo::UndoBatch::default();
    seed.restore(bitcoin_rs_utxo::UtxoAdd::new(
        funded,
        TxOut {
            value: Amount::from_sat(funded_value),
            script_pubkey: Script::from_bytes(op_true_script()),
        },
        false,
        0,
    ));
    utxo.undo_block(&seed)?;
    let outputs_before = utxo.len();
    let funded_before = utxo
        .get(&funded)
        .ok_or("seeded output missing before apply")?;

    let spend = spending_transaction_to_script(funded, 0xFFFF_FFFF, op_true_script());
    let block = mined_block_with_prev_hash_and_transactions(
        genesis.block_hash(),
        vec![coinbase_transaction(1), spend.clone()],
    )?;
    let applied = handles.apply_block(&block)?.tip;
    assert_eq!(applied.height, 1, "the block must connect first");
    assert!(
        utxo.get(&funded).is_none(),
        "the spend must consume the funded output"
    );

    let restored_tip = handles.disconnect_block(&block)?.parent_tip;

    assert_eq!(
        restored_tip.hash, genesis_hash,
        "tip must return to genesis"
    );
    assert_eq!(restored_tip.height, 0, "height must return to genesis");
    assert_eq!(
        handles
            .applied_tip
            .load()
            .as_ref()
            .map(|tip| tip.hash)
            .ok_or("applied tip cleared by disconnect")?,
        genesis_hash,
        "the published applied tip must match the returned one"
    );
    assert_eq!(
        utxo.len(),
        outputs_before,
        "the UTXO set must return to its exact prior size"
    );
    let funded_after = utxo.get(&funded).ok_or("spent output was not restored")?;
    assert_eq!(
        funded_after, funded_before,
        "the restored output must be byte-identical to the one spent"
    );
    assert!(
        utxo.get(&OutPoint::new(spend.txid(), 0)).is_none(),
        "outputs the block created must be gone"
    );
    Ok(())
}

/// RPC reads blocks from the derived `BlockLog`. Leaving the entry there
/// would let `getblock` keep answering for a block the chain no longer
/// contains.
#[test]
#[allow(clippy::arc_with_non_send_sync)]
fn disconnect_drops_the_rpc_block_record() -> Result<(), Box<dyn std::error::Error>> {
    let genesis = Network::Regtest.genesis_block();
    let utxo = Arc::new(UtxoSet::new());
    let handles = apply_handles_without_tx_index(Network::Regtest, Arc::clone(&utxo));
    let followers = crate::chain_effects::ChainFollowers::noop();
    let genesis_hash = Hash256::from(genesis.block_hash());
    let genesis_tip = applied_header_tip(&handles, genesis_hash, &genesis, 0)?;
    handles.applied_tip.store(Some(Arc::new(genesis_tip)));
    let records_before = followers.effects().block_log().read().len();

    let block = mined_block_with_prev_hash_and_transactions(
        genesis.block_hash(),
        vec![coinbase_transaction(1)],
    )?;
    let block_hash = block.block_hash();
    apply_followed(&handles, &followers, &block)?;
    assert!(
        followers
            .effects()
            .block_log()
            .read()
            .iter()
            .any(|record| record.hash == block_hash),
        "connection must publish the record this test then removes"
    );

    disconnect_followed(&handles, &followers, &block)?;

    assert!(
        !followers
            .effects()
            .block_log()
            .read()
            .iter()
            .any(|record| record.hash == block_hash),
        "RPC must not keep serving a disconnected block"
    );
    assert_eq!(
        followers.effects().block_log().read().len(),
        records_before,
        "exactly the one record must go"
    );
    Ok(())
}

/// The marker's two ends, on the real disconnect path. Arming without
/// disarming would refuse every later start; disarming without arming would
/// leave the crash window unguarded. Only running the real disconnect can
/// show both ends are wired, so this does not call the store directly.
#[test]
#[allow(clippy::arc_with_non_send_sync)]
fn a_clean_disconnect_leaves_no_in_flight_marker() -> Result<(), Box<dyn std::error::Error>> {
    let genesis = Network::Regtest.genesis_block();
    let utxo = Arc::new(UtxoSet::new());
    let handles = apply_handles_without_tx_index(Network::Regtest, Arc::clone(&utxo));
    let genesis_hash = Hash256::from(genesis.block_hash());
    let genesis_tip = applied_header_tip(&handles, genesis_hash, &genesis, 0)?;
    handles.applied_tip.store(Some(Arc::new(genesis_tip)));

    let block = mined_block_with_prev_hash_and_transactions(
        genesis.block_hash(),
        vec![coinbase_transaction(1)],
    )?;
    handles.apply_block(&block)?;
    assert_eq!(
        handles.undo_store.load_disconnect_marker()?,
        None,
        "connecting a block must not arm the disconnect marker"
    );

    handles.disconnect_block(&block)?;

    // Deliberately still set. The UTXO undo is complete in memory, but the
    // undo record is durable while the UTXO set and tip are not, so the
    // marker is owed a checkpoint before it may go.
    let marker = handles
        .undo_store
        .load_disconnect_marker()?
        .ok_or("a completed disconnect must leave a marker for the checkpoint")?;
    assert_eq!(
        marker.phase,
        DisconnectPhase::RolledBack,
        "a completed rollback must be recorded as such, not left in flight"
    );
    Ok(())
}

/// `coin_stats` needs no inverse feed of its own, and this proves it rather
/// than assuming it. It is registered as the `UtxoSet` change listener, so
/// `undo_block` already delivers the inverse as ordinary inserts and
/// removals: restores arrive as inserts, removes as removals. Adding a
/// second feed on the disconnect path would double-count.
#[test]
#[allow(clippy::arc_with_non_send_sync)]
fn disconnect_returns_coin_stats_to_their_prior_value() -> Result<(), Box<dyn std::error::Error>> {
    let genesis = Network::Regtest.genesis_block();
    let mut utxo = UtxoSet::new();
    let listener = bitcoin_rs_utxo::stats::CoinStatsListener::new(
        bitcoin_rs_utxo::stats::CoinStats::default(),
    );
    utxo.set_listener(Box::new(listener.clone()));
    let utxo = Arc::new(utxo);
    let mut handles = apply_handles_without_tx_index(Network::Regtest, Arc::clone(&utxo));
    handles.coin_stats = Arc::new(listener);
    let genesis_hash = Hash256::from(genesis.block_hash());
    let genesis_tip = applied_header_tip(&handles, genesis_hash, &genesis, 0)?;
    handles.applied_tip.store(Some(Arc::new(genesis_tip)));
    let before = handles.coin_stats.snapshot();

    let block = mined_block_with_prev_hash_and_transactions(
        genesis.block_hash(),
        vec![coinbase_transaction(1)],
    )?;
    handles.apply_block(&block)?;
    let connected = handles.coin_stats.snapshot();
    assert_ne!(
        connected, before,
        "connection must move the stats, or the test proves nothing"
    );

    handles.disconnect_block(&block)?;

    // Every field, not a chosen one. Comparing only the per-coin fields
    // would pass while `height` and `tx_count` stayed on the child, which
    // is the gap that made the block-level rewind necessary.
    //
    // MuHash is compared by digest rather than by struct. It is a ratio of
    // a numerator and a denominator, so inserting a coin and removing it
    // leaves the two equal but not back at the limbs they started from. The
    // digest is the observable value and it does return.
    let after = handles.coin_stats.snapshot();
    assert_eq!(
        after.muhash.finalize_hash(),
        before.muhash.finalize_hash(),
        "the MuHash digest must return to its prior value"
    );
    assert_eq!(after.height, before.height, "height must return");
    assert_eq!(
        after.total_amount, before.total_amount,
        "total amount must return"
    );
    assert_eq!(after.bogo_size, before.bogo_size, "bogo size must return");
    assert_eq!(after.tx_count, before.tx_count, "tx count must return");
    assert_eq!(
        after.utxo_count, before.utxo_count,
        "utxo count must return"
    );
    Ok(())
}
