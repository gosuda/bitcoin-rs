use super::*;

#[test]
fn build_utxo_changes_excludes_oversized_scripts() -> Result<(), Box<dyn std::error::Error>> {
    let mut coinbase = coinbase_transaction(0x70);
    coinbase.outputs.push(TxOut {
        value: Amount::from_sat(0),
        script_pubkey: Script::from_bytes(vec![0x51; MAX_SCRIPT_SIZE]),
    });
    coinbase.outputs.push(TxOut {
        value: Amount::from_sat(0),
        script_pubkey: Script::from_bytes(vec![0x51; MAX_SCRIPT_SIZE + 1]),
    });
    let txid = coinbase.txid();
    let block = block_with_transaction(coinbase);
    let scratch = ApplyScratch::new(&block, false);
    let (add_cap, rem_cap) = scratch.utxo_change_capacity();
    let (changes, _undo, _totals) = build_block_changes(
        &block,
        1,
        scratch.txids(),
        scratch.same_block_spent(),
        add_cap,
        rem_cap,
        &ResolvedUtxoView::empty(),
        None,
        MAX_SCRIPT_SIZE,
    )?;
    let utxo = UtxoSet::new();

    utxo.commit_borrowed_block(&changes, &Hash256::from_le_bytes(&[0x73; 32]))?;

    assert!(utxo.get(&OutPoint::new(txid, 0)).is_some());
    assert!(utxo.get(&OutPoint::new(txid, 1)).is_some());
    assert!(utxo.get(&OutPoint::new(txid, 2)).is_none());
    Ok(())
}

#[test]
fn coinbase_maturity_rejects_same_block_coinbase_spend() {
    let coinbase = coinbase_transaction(0x64);
    let coinbase_outpoint = OutPoint::new(coinbase.txid(), 0);
    let spend = spending_transaction_to_script(coinbase_outpoint, u32::MAX, op_true_script());
    let block = block_with_transactions(vec![coinbase, spend]);
    let handles = empty_apply_handles();

    let error = match check_coinbase_maturity_with_tx_plan(
        &handles,
        &block,
        &tx_plan(&block),
        &block_txids(&block),
        Arc::new(ResolvedUtxoView::resolve(
            handles.utxo.as_ref(),
            &block,
            &tx_plan(&block),
        )),
        1,
    ) {
        Ok(()) => panic!("same-block coinbase spend must fail maturity"),
        Err(error) => error,
    };
    assert_bip_error(&error, "COINBASE_MATURITY");
}

#[test]
fn verify_block_transactions_defers_same_block_coinbase_spend_to_maturity() {
    let mut coinbase = coinbase_transaction(0x65);
    coinbase.outputs[0].script_pubkey = Script::from_bytes(op_true_script());
    let coinbase_outpoint = OutPoint::new(coinbase.txid(), 0);
    let spend = spending_transaction_to_script(coinbase_outpoint, u32::MAX, op_true_script());
    let block = block_with_transactions(vec![coinbase, spend]);
    let handles = empty_apply_handles();

    assert!(
        verify_block_transactions(
            &handles,
            &block,
            &mut bitcoin_rs_consensus::BlockView::new(&block.txs, block_txids(&block)),
            &tx_plan(&block),
            Arc::new(ResolvedUtxoView::resolve(
                handles.utxo.as_ref(),
                &block,
                &tx_plan(&block)
            )),
            &validation_context(&block, 1, 0, bitcoin_rs_script::VerifyFlags::NONE),
            BlockProvenance::Network,
            &kernel_block_of(&block),
        )
        .is_ok()
    );
    let error = match check_coinbase_maturity_with_tx_plan(
        &handles,
        &block,
        &tx_plan(&block),
        &block_txids(&block),
        Arc::new(ResolvedUtxoView::resolve(
            handles.utxo.as_ref(),
            &block,
            &tx_plan(&block),
        )),
        1,
    ) {
        Ok(()) => panic!("same-block coinbase spend must fail maturity"),
        Err(error) => error,
    };
    assert_bip_error(&error, "COINBASE_MATURITY");
}

#[test]
fn bip68_height_lock_enforces_boundary_when_csv_active() -> Result<(), Box<dyn std::error::Error>> {
    let previous_output = OutPoint::new(fixture_txid(0x68), 0);
    let utxo = utxo_with_output(previous_output, BIP68_TEST_PREVOUT_HEIGHT)?;
    let handles = apply_handles(utxo);
    let block = block_with_transaction(spending_transaction_to_script(
        previous_output,
        2,
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
            validation: &validation_context(&block, 101, 0, bitcoin_rs_script::VerifyFlags::NONE),
            median_time_past: 0,
            softfork_state: active,
            previous_tip_id: None,
        },
    ) {
        Ok(()) => panic!("BIP68 height lock must reject one block before maturity"),
        Err(error) => error,
    };
    assert_bip_error(&error, "BIP68");
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
                    102,
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
fn bip68_time_lock_enforces_mtp_boundary_when_csv_active() -> Result<(), Box<dyn std::error::Error>>
{
    let previous_output = OutPoint::new(fixture_txid(0x69), 0);
    let utxo = utxo_with_output(previous_output, BIP68_TEST_PREVOUT_HEIGHT)?;
    let handles = apply_handles(utxo);
    let previous_tip_id = seed_block_tree_for_bip68_time(&handles)?;
    let sequence = BIP68_TYPE_FLAG | 2;
    let block = block_with_transaction(spending_transaction_to_script(
        previous_output,
        sequence,
        op_true_script(),
    ));
    let active = softfork_state(true);
    let required_mtp = BIP68_TEST_PREVOUT_MTP + 2 * BIP68_TIME_GRANULARITY_SECONDS;

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
            median_time_past: required_mtp - 1,
            softfork_state: active,
            previous_tip_id: Some(previous_tip_id),
        },
    ) {
        Ok(()) => panic!("BIP68 time lock must reject one second before maturity"),
        Err(error) => error,
    };
    assert_bip_error(&error, "BIP68");
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
                validation: &validation_context(&block, 0, 0, bitcoin_rs_script::VerifyFlags::NONE),
                median_time_past: required_mtp,
                softfork_state: active,
                previous_tip_id: Some(previous_tip_id),
            },
        )
        .is_ok()
    );
    Ok(())
}

#[test]
fn bip68_time_lock_uses_mtp_before_prevout_height() -> Result<(), Box<dyn std::error::Error>> {
    let previous_output = OutPoint::new(fixture_txid(0x67), 0);
    let prevout_height = 3;
    let utxo = utxo_with_output(previous_output, prevout_height)?;
    let handles = apply_handles(utxo);
    let previous_tip_id = seed_block_tree_with_times(&handles, &[100, 200, 300, 400])?;
    let block = block_with_transaction(spending_transaction_to_script(
        previous_output,
        BIP68_TYPE_FLAG,
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
                    prevout_height + 1,
                    0,
                    bitcoin_rs_script::VerifyFlags::NONE
                ),
                median_time_past: 200,
                softfork_state: softfork_state(true),
                previous_tip_id: Some(previous_tip_id),
            },
        )
        .is_ok()
    );
    Ok(())
}

#[test]
fn bip68_time_lock_accepts_multiple_prevouts_at_same_height()
-> Result<(), Box<dyn std::error::Error>> {
    let first_previous_output = OutPoint::new(fixture_txid(0x66), 0);
    let second_previous_output = OutPoint::new(fixture_txid(0x65), 0);
    let prevout_height = BIP68_TEST_PREVOUT_HEIGHT;
    let utxo = utxo_with_outputs_at_height(
        &[first_previous_output, second_previous_output],
        prevout_height,
    )?;
    let handles = apply_handles(utxo);
    let previous_tip_id = seed_block_tree_for_bip68_time(&handles)?;
    let block = block_with_transactions(vec![
        spending_transaction_to_script(first_previous_output, BIP68_TYPE_FLAG, op_true_script()),
        spending_transaction_to_script(second_previous_output, BIP68_TYPE_FLAG, op_true_script()),
    ]);

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
                    prevout_height + 1,
                    0,
                    bitcoin_rs_script::VerifyFlags::NONE
                ),
                median_time_past: BIP68_TEST_PREVOUT_MTP,
                softfork_state: softfork_state(true),
                previous_tip_id: Some(previous_tip_id),
            },
        )
        .is_ok()
    );
    Ok(())
}

/// Drives the real apply entry into active CSV with a version-2 spend whose
/// relative height lock is unmet, pinning two facts about the apply path:
/// the BIP68 verdict must propagate out of `apply_block` as
/// `ApplyError::Consensus(ConsensusError::Bip)`, and it must do so before
/// the first write — a gate deleted or reordered after the UTXO commit
/// would leave the tip advanced, the prevout spent, or the header
/// installed, and every one of those is asserted against here.
#[test]
fn apply_block_propagates_unmet_bip68_sequence_lock_before_mutation()
-> Result<(), Box<dyn std::error::Error>> {
    // CSV activates on regtest at height 432, so the applied tip sits at
    // 431 and the block connects at the first BIP68-enforcing height. The
    // prevout is a tip-block output and the sequence asks for two blocks
    // of age, making BIP68 the only rule the block violates.
    let prevout_height = 431;
    let previous_output = OutPoint::new(fixture_txid(0x6e), 0);
    let utxo = utxo_with_output(previous_output, prevout_height)?;
    let handles = apply_handles_for_network(Network::Regtest, Arc::clone(&utxo));
    let tip_id = seed_block_tree_for_bip68_time_at_height(&handles, prevout_height)?;
    let seeded_tip = handles
        .block_tree
        .read()
        .tip()
        .filter(|tip| tip.tip_id == tip_id)
        .ok_or_else(|| std::io::Error::other("seeded tip missing"))?;
    handles.applied_tip.store(Some(Arc::clone(&seeded_tip)));

    // Version 2 with a sequence lacking the disable flag is what arms the
    // relative lock; version 1 or a disabled sequence would bypass it.
    let spend = spending_transaction_to_script(previous_output, 2, op_true_script());
    let block = mined_block_with_prev_hash_and_transactions(
        BlockHash::from(seeded_tip.hash),
        vec![coinbase_transaction(0x6f), spend],
    )?;

    let error = match handles.apply_block(&block).map(|outcome| outcome.tip) {
        Ok(_) => panic!("unmet BIP68 sequence lock must reject the block"),
        Err(error) => error,
    };
    assert_bip_error(&error, "BIP68");

    // No mutation: tip, UTXO set, and block tree are exactly as seeded.
    let tip_after = handles
        .applied_tip
        .load_full()
        .ok_or_else(|| std::io::Error::other("applied tip vanished"))?;
    assert_eq!(tip_after.height, prevout_height);
    assert_eq!(tip_after.hash, seeded_tip.hash);
    assert!(
        utxo.get(&previous_output).is_some(),
        "the spent prevout must survive a rejected apply"
    );
    assert!(
        utxo.get(&OutPoint::new(block.txs[1].txid(), 0)).is_none(),
        "a rejected block must not install its outputs"
    );
    assert!(
        handles
            .block_tree
            .read()
            .lookup(Hash256::from(block.block_hash()))
            .is_none(),
        "a rejected block must not enter the block tree"
    );
    Ok(())
}

#[test]
fn bip68_time_lock_uses_previous_tip_mtp_for_same_block_prevout()
-> Result<(), Box<dyn std::error::Error>> {
    let handles = empty_apply_handles();
    let previous_tip_id = seed_block_tree_for_bip68_time_at_height(&handles, 100)?;
    let funding_tx = transaction(0x6c);
    let funding_outpoint = OutPoint::new(funding_tx.txid(), 0);
    let same_block_spend =
        spending_transaction_to_script(funding_outpoint, BIP68_TYPE_FLAG, op_true_script());
    let block = block_with_transactions(vec![funding_tx, same_block_spend]);

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
                median_time_past: BIP68_TEST_PREVOUT_MTP,
                softfork_state: softfork_state(true),
                previous_tip_id: Some(previous_tip_id),
            },
        )
        .is_ok()
    );
    Ok(())
}
