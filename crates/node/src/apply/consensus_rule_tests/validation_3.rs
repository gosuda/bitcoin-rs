use super::*;

#[test]
fn bip68_time_lock_rejects_delayed_same_block_prevout() -> Result<(), Box<dyn std::error::Error>> {
    let handles = empty_apply_handles();
    let previous_tip_id = seed_block_tree_for_bip68_time_at_height(&handles, 100)?;
    let funding_tx = transaction(0x6d);
    let funding_outpoint = OutPoint::new(funding_tx.txid(), 0);
    let same_block_spend =
        spending_transaction_to_script(funding_outpoint, BIP68_TYPE_FLAG | 1, op_true_script());
    let block = block_with_transactions(vec![funding_tx, same_block_spend]);

    let error = match check_bip68_sequence_locks(
        &handles,
        &block,
        &tx_plan(&block),
        &block_txids(&block),
        Arc::new(ResolvedUtxoView::resolve(
            handles.utxo.as_ref(),
            &block,
            &tx_plan(&block),
        )),
        Bip68Context {
            validation: &validation_context(&block, 101, 0, bitcoin_rs_script::VerifyFlags::NONE),
            median_time_past: BIP68_TEST_PREVOUT_MTP,
            softfork_state: softfork_state(true),
            previous_tip_id: Some(previous_tip_id),
        },
    ) {
        Ok(()) => {
            panic!("same-block time-based relative lock must not mature in the same block")
        }
        Err(error) => error,
    };
    assert_bip_error_reason_contains(&error, "BIP68", "time-based lock unmet");
    Ok(())
}

#[test]
fn bip68_time_lock_rejects_missing_previous_tip_context() -> Result<(), Box<dyn std::error::Error>>
{
    let previous_output = OutPoint::new(fixture_txid(0x6a), 0);
    let utxo = utxo_with_output(previous_output, BIP68_TEST_PREVOUT_HEIGHT)?;
    let handles = apply_handles(utxo);
    let sequence = BIP68_TYPE_FLAG | 1;
    let block = block_with_transaction(spending_transaction_to_script(
        previous_output,
        sequence,
        op_true_script(),
    ));
    let active = softfork_state(true);

    let error = match check_bip68_sequence_locks(
        &handles,
        &block,
        &tx_plan(&block),
        &block_txids(&block),
        Arc::new(ResolvedUtxoView::resolve(
            handles.utxo.as_ref(),
            &block,
            &tx_plan(&block),
        )),
        Bip68Context {
            validation: &validation_context(&block, 0, 0, bitcoin_rs_script::VerifyFlags::NONE),
            median_time_past: BIP68_TEST_PREVOUT_MTP + BIP68_TIME_GRANULARITY_SECONDS,
            softfork_state: active,
            previous_tip_id: None,
        },
    ) {
        Ok(()) => panic!("BIP68 time lock must reject missing previous tip context"),
        Err(error) => error,
    };
    assert_bip_error(&error, "BIP68");
    Ok(())
}

#[test]
fn bip68_time_lock_rejects_missing_prevout_ancestor_context()
-> Result<(), Box<dyn std::error::Error>> {
    let previous_output = OutPoint::new(fixture_txid(0x6b), 0);
    let utxo = utxo_with_output(previous_output, BIP68_TEST_PREVOUT_HEIGHT)?;
    let handles = apply_handles(utxo);
    let previous_tip_id = seed_block_tree_for_bip68_time_at_height(&handles, 0)?;
    let sequence = BIP68_TYPE_FLAG | 1;
    let block = block_with_transaction(spending_transaction_to_script(
        previous_output,
        sequence,
        op_true_script(),
    ));
    let active = softfork_state(true);

    let error = match check_bip68_sequence_locks(
        &handles,
        &block,
        &tx_plan(&block),
        &block_txids(&block),
        Arc::new(ResolvedUtxoView::resolve(
            handles.utxo.as_ref(),
            &block,
            &tx_plan(&block),
        )),
        Bip68Context {
            validation: &validation_context(&block, 0, 0, bitcoin_rs_script::VerifyFlags::NONE),
            median_time_past: BIP68_TEST_PREVOUT_MTP + BIP68_TIME_GRANULARITY_SECONDS,
            softfork_state: active,
            previous_tip_id: Some(previous_tip_id),
        },
    ) {
        Ok(()) => panic!("BIP68 time lock must reject missing prevout ancestry"),
        Err(error) => error,
    };
    assert_bip_error(&error, "BIP68");
    Ok(())
}

#[test]
fn bip68_inactive_csv_skips_unmet_sequence_lock() -> Result<(), Box<dyn std::error::Error>> {
    let previous_output = OutPoint::new(fixture_txid(0x70), 0);
    let utxo = utxo_with_output(previous_output, BIP68_TEST_PREVOUT_HEIGHT)?;
    let handles = apply_handles(utxo);
    let block = block_with_transaction(spending_transaction_to_script(
        previous_output,
        2,
        op_true_script(),
    ));

    assert!(
        check_bip68_sequence_locks(
            &handles,
            &block,
            &tx_plan(&block),
            &block_txids(&block),
            Arc::new(ResolvedUtxoView::resolve(
                handles.utxo.as_ref(),
                &block,
                &tx_plan(&block)
            )),
            Bip68Context {
                validation: &validation_context(
                    &block,
                    101,
                    0,
                    bitcoin_rs_script::VerifyFlags::NONE
                ),
                median_time_past: 0,
                softfork_state: softfork_state(false),
                previous_tip_id: None,
            },
        )
        .is_ok()
    );
    Ok(())
}

#[test]
fn bip68_ignores_version_one_and_disabled_sequences() -> Result<(), Box<dyn std::error::Error>> {
    let previous_output = OutPoint::new(fixture_txid(0x71), 0);
    let utxo = utxo_with_output(previous_output, BIP68_TEST_PREVOUT_HEIGHT)?;
    let handles = apply_handles(utxo);
    let active = softfork_state(true);

    let version_one_block =
        block_with_transaction(spending_transaction_with_version(previous_output, 2, 1));
    assert!(
        check_bip68_sequence_locks(
            &handles,
            &version_one_block,
            &tx_plan(&version_one_block),
            &block_txids(&version_one_block),
            Arc::new(ResolvedUtxoView::resolve(
                handles.utxo.as_ref(),
                &version_one_block,
                &tx_plan(&version_one_block)
            )),
            Bip68Context {
                validation: &validation_context(
                    &version_one_block,
                    101,
                    0,
                    bitcoin_rs_script::VerifyFlags::NONE
                ),
                median_time_past: 0,
                softfork_state: active,
                previous_tip_id: None,
            },
        )
        .is_ok()
    );

    let disabled_block = block_with_transaction(spending_transaction_to_script(
        previous_output,
        BIP68_DISABLE_FLAG | 2,
        op_true_script(),
    ));
    assert!(
        check_bip68_sequence_locks(
            &handles,
            &disabled_block,
            &tx_plan(&disabled_block),
            &block_txids(&disabled_block),
            Arc::new(ResolvedUtxoView::resolve(
                handles.utxo.as_ref(),
                &disabled_block,
                &tx_plan(&disabled_block)
            )),
            Bip68Context {
                validation: &validation_context(
                    &disabled_block,
                    101,
                    0,
                    bitcoin_rs_script::VerifyFlags::NONE
                ),
                median_time_past: 0,
                softfork_state: active,
                previous_tip_id: None,
            },
        )
        .is_ok()
    );
    Ok(())
}

#[test]
#[allow(clippy::arc_with_non_send_sync)]
fn bip30_rejects_duplicate_txid_when_only_higher_vout_is_live()
-> Result<(), Box<dyn std::error::Error>> {
    let duplicate_tx = transaction(7);
    let duplicate_txid = duplicate_tx.txid();
    let utxo = Arc::new(UtxoSet::new());
    let mut changes = BlockChanges::default();
    changes.add(UtxoAdd::new(
        OutPoint::new(duplicate_txid, 1),
        TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: Script::new(),
        },
        false,
        0,
    ));
    utxo.commit_block(&changes, &Hash256::from_le_bytes(&[9; 32]))?;

    let handles = apply_handles(utxo);
    let block = Block {
        header: Header {
            version: 1,
            prev_blockhash: BlockHash::default(),
            merkle_root: Hash256::default(),
            time: 0,
            bits: CompactTarget::from_consensus(0),
            nonce: 0,
        },
        txs: vec![duplicate_tx],
    };

    let txids = [duplicate_txid];
    let error = match check_bip30_and_bip34(&handles, &block, 1, &txids, None) {
        Ok(()) => panic!("duplicate txid with live vout 1 must violate BIP30"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        ApplyError::Consensus(bitcoin_rs_consensus::ConsensusError::Bip { bip: "BIP30", .. })
    ));
    Ok(())
}

#[test]
#[allow(clippy::arc_with_non_send_sync)]
fn bip30_skips_duplicate_scan_after_known_bip34_activation()
-> Result<(), Box<dyn std::error::Error>> {
    let height = Network::Testnet3
        .bip34_activation_height()
        .checked_add(1)
        .ok_or_else(|| std::io::Error::other("activation height overflow"))?;
    let duplicate_tx = coinbase_transaction_with_height(height);
    let duplicate_txid = duplicate_tx.txid();
    let utxo = Arc::new(UtxoSet::new());
    let mut changes = BlockChanges::default();
    changes.add(UtxoAdd::new(
        OutPoint::new(duplicate_txid, 0),
        TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: Script::new(),
        },
        false,
        0,
    ));
    utxo.commit_block(&changes, &Hash256::from_le_bytes(&[9; 32]))?;

    let handles = apply_handles_for_network(Network::Testnet3, utxo);
    let previous_tip_id = seed_known_bip34_activation_chain(&handles, Network::Testnet3)?;
    let block = block_with_transaction(duplicate_tx);
    let txids = [duplicate_txid];

    check_bip30_and_bip34(&handles, &block, height, &txids, Some(previous_tip_id))?;
    Ok(())
}

#[test]
#[allow(clippy::arc_with_non_send_sync)]
fn bip30_duplicate_scan_runs_without_known_bip34_activation_hash()
-> Result<(), Box<dyn std::error::Error>> {
    let height = Network::Regtest
        .bip34_activation_height()
        .checked_add(1)
        .ok_or_else(|| std::io::Error::other("activation height overflow"))?;
    let duplicate_tx = coinbase_transaction_with_height(height);
    let duplicate_txid = duplicate_tx.txid();
    let utxo = Arc::new(UtxoSet::new());
    let mut changes = BlockChanges::default();
    changes.add(UtxoAdd::new(
        OutPoint::new(duplicate_txid, 0),
        TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: Script::new(),
        },
        false,
        0,
    ));
    utxo.commit_block(&changes, &Hash256::from_le_bytes(&[9; 32]))?;

    let handles = apply_handles_for_network(Network::Regtest, utxo);
    let block = block_with_transaction(duplicate_tx);
    let txids = [duplicate_txid];
    let error = match check_bip30_and_bip34(&handles, &block, height, &txids, None) {
        Ok(()) => panic!("regtest has no fixed BIP34 activation hash and must scan BIP30"),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        ApplyError::Consensus(bitcoin_rs_consensus::ConsensusError::Bip { bip: "BIP30", .. })
    ));
    Ok(())
}

#[test]
#[allow(clippy::arc_with_non_send_sync)]
fn bip30_duplicate_scan_runs_at_core_recheck_limit() -> Result<(), Box<dyn std::error::Error>> {
    let duplicate_tx = coinbase_transaction_with_height(BIP34_IMPLIES_BIP30_LIMIT);
    let duplicate_txid = duplicate_tx.txid();
    let utxo = Arc::new(UtxoSet::new());
    let mut changes = BlockChanges::default();
    changes.add(UtxoAdd::new(
        OutPoint::new(duplicate_txid, 0),
        TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: Script::new(),
        },
        false,
        0,
    ));
    utxo.commit_block(&changes, &Hash256::from_le_bytes(&[9; 32]))?;

    let handles = apply_handles_for_network(Network::Mainnet, utxo);
    let block = block_with_transaction(duplicate_tx);
    let txids = [duplicate_txid];
    let error =
        match check_bip30_and_bip34(&handles, &block, BIP34_IMPLIES_BIP30_LIMIT, &txids, None) {
            Ok(()) => panic!("Core recheck limit must keep BIP30 duplicate scanning enabled"),
            Err(error) => error,
        };

    assert!(matches!(
        error,
        ApplyError::Consensus(bitcoin_rs_consensus::ConsensusError::Bip { bip: "BIP30", .. })
    ));
    Ok(())
}

#[test]
fn daa_retarget_caps_slow_timespan_at_pow_limit() -> Result<(), Box<dyn std::error::Error>> {
    let handles = empty_apply_handles();
    let interval = handles.network.retarget_interval();
    let expected_timespan = interval * 600;
    let parent_hash = seed_pow_chain(
        &handles,
        MAINNET_POW_LIMIT_BITS,
        DAA_ANCHOR_TIME,
        DAA_ANCHOR_TIME + (expected_timespan * 4) + 1,
        interval - 1,
    )?;
    let block = block_with_pow_header(
        parent_hash,
        MAINNET_POW_LIMIT_BITS,
        DAA_ANCHOR_TIME + (expected_timespan * 4) + 600,
        interval,
    );

    assert!(check_pow_limit_and_continuity_for_seeded_tip(&handles, &block, interval).is_ok());
    Ok(())
}

/// A coinbase may not pay itself more than the subsidy plus the fees.
///
/// Nothing else in the node bounds this. Block rules check structure, and
/// per-transaction verification exempts the coinbase because it has no
/// inputs to weigh its outputs against -- so without this rule a miner can
/// simply write any amount into the coinbase and the block is accepted.
/// That is inflation, and it is what this test would have demonstrated
/// before the rule existed.
///
/// The paired accept is the point: the same block, one satoshi lower, must
/// apply. Otherwise a rejection for any unrelated reason would read as
/// success here.
#[test]
#[allow(clippy::arc_with_non_send_sync)]
fn apply_rejects_a_coinbase_that_pays_more_than_the_subsidy() {
    let subsidy =
        bitcoin_rs_consensus::block_subsidy(1, Network::Regtest.subsidy_halving_interval());
    assert_eq!(
        subsidy,
        50 * 100_000_000,
        "regtest height 1 pays the full subsidy"
    );

    let over = apply_coinbase_only_block(subsidy + 1);
    assert!(
        matches!(
            &over,
            Err(ApplyError::Consensus(
                bitcoin_rs_consensus::ConsensusError::CoinbaseAmount { paid, allowed }
            )) if *paid == subsidy + 1 && *allowed == subsidy
        ),
        "a coinbase claiming one satoshi too much must be refused, got {over:?}"
    );

    let exact = apply_coinbase_only_block(subsidy);
    assert!(
        exact.is_ok(),
        "the same block claiming exactly the subsidy must apply, got {exact:?}"
    );
}
