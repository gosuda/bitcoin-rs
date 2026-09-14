use super::*;

#[test]
fn bip68_time_lock_rejects_delayed_same_block_prevout() -> Result<(), Box<dyn std::error::Error>> {
    let handles = empty_apply_handles();
    let previous_tip_id = seed_block_tree_for_bip68_time_at_height(&handles, 100)?;
    let funding_tx = transaction(0x6d);
    let funding_outpoint = OutPoint::new(funding_tx.txid(), 0);
    let same_block_spend = spending_transaction_to_script(
        funding_outpoint,
        bitcoin_rs_consensus::bip68::SEQUENCE_LOCKTIME_TYPE_FLAG | 1,
        op_true_script(),
    );
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
    let sequence = bitcoin_rs_consensus::bip68::SEQUENCE_LOCKTIME_TYPE_FLAG | 1;
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
            median_time_past: BIP68_TEST_PREVOUT_MTP
                + bitcoin_rs_consensus::bip68::SEQUENCE_LOCKTIME_GRANULARITY_SECONDS,
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
    let sequence = bitcoin_rs_consensus::bip68::SEQUENCE_LOCKTIME_TYPE_FLAG | 1;
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
            median_time_past: BIP68_TEST_PREVOUT_MTP
                + bitcoin_rs_consensus::bip68::SEQUENCE_LOCKTIME_GRANULARITY_SECONDS,
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
        bitcoin_rs_consensus::bip68::SEQUENCE_LOCKTIME_DISABLE_FLAG | 2,
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
