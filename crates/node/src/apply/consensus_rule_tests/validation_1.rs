use super::*;

#[test]
fn block_local_utxo_view_metadata_tracks_coinbase_and_height() -> Result<(), ApplyError> {
    let coinbase = coinbase_transaction(0x46);
    let transaction = spending_transaction_to_script(
        OutPoint::new(fixture_txid(0x47), 0),
        u32::MAX,
        op_true_script(),
    );
    let coinbase_outpoint = OutPoint::new(coinbase.txid(), 0);
    let transaction_outpoint = OutPoint::new(transaction.txid(), 0);
    let block = block_with_transactions(vec![coinbase, transaction]);
    let mut view = BlockLocalUtxoView::new(Arc::new(ResolvedUtxoView::empty()), &block.txs, 42, 2);

    view.add_outputs(0, block.txs[0].txid(), block.txs[0].outputs.len())?;
    view.add_outputs(1, block.txs[1].txid(), block.txs[1].outputs.len())?;

    let coinbase_meta = view
        .lookup_meta(&coinbase_outpoint)
        .ok_or(ApplyError::HeightOverflow(42))?;
    let transaction_meta = view
        .lookup_meta(&transaction_outpoint)
        .ok_or(ApplyError::HeightOverflow(42))?;
    assert!(coinbase_meta.coinbase);
    assert!(!transaction_meta.coinbase);
    assert_eq!(coinbase_meta.height, 42);
    assert_eq!(transaction_meta.height, 42);
    Ok(())
}

/// The unified full-verify path resolves same-block spends in order (tx1 spends
/// tx0's output, forcing the overlay walk) yet still surfaces the *earlier*
/// transaction's script failure deterministically — the node rewrite preserves
/// error identity through `verify_block_input_scripts`. Feature-agnostic: the
/// Script reason differs between the portable and kernel engines, so only the
/// variant and input index are asserted.
#[test]
fn verify_block_transactions_same_block_spend_surfaces_earlier_bad_script()
-> Result<(), Box<dyn std::error::Error>> {
    let base_prevout = OutPoint::new(fixture_txid(0x68), 0);
    let utxo = Arc::new(UtxoSet::new());
    let mut changes = BlockChanges::default();
    changes.add(UtxoAdd::new(
        base_prevout,
        TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: Script::from_bytes(vec![0x87]),
        },
        false,
        1,
    ));
    utxo.commit_block(&changes, &Hash256::from_le_bytes(&[9; 32]))?;
    let handles = apply_handles(utxo);

    // tx0 (funding) fails its script against the OP_EQUAL prevout.
    let mut script_sig = push_int(7);
    script_sig.extend_from_slice(&push_int(8));
    let funding_tx = Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: base_prevout,
            script_sig: Script::from_bytes(script_sig),
            sequence: Sequence::from_consensus(u32::MAX),
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: Script::from_bytes(op_true_script()),
        }],
        lock_time: LockTime::from_consensus(0),
    };
    let funding_outpoint = OutPoint::new(funding_tx.txid(), 0);
    // tx1 spends tx0's output inside the block, forcing the overlay walk.
    let same_block_spend =
        spending_transaction_to_script(funding_outpoint, u32::MAX, op_true_script());
    let block = block_with_transactions(vec![funding_tx, same_block_spend]);
    let plan = tx_plan(&block);
    assert!(plan.needs_local_utxo_overlay);

    let error = match verify_block_transactions(
        &handles,
        &block,
        &mut bitcoin_rs_consensus::BlockView::new(&block.txs, block_txids(&block)),
        &plan,
        Arc::new(ResolvedUtxoView::resolve(
            handles.utxo.as_ref(),
            &block,
            &plan,
        )),
        &validation_context(&block, 2, 0, bitcoin_rs_script::VerifyFlags::MANDATORY),
        BlockProvenance::Network,
        &kernel_block_of(&block),
    ) {
        Ok(()) => panic!("earlier tx bad script must reject the block"),
        Err(error) => error,
    };
    assert!(
        matches!(
            error,
            ApplyError::Consensus(bitcoin_rs_consensus::ConsensusError::Script {
                input_index: 0,
                ..
            })
        ),
        "expected earlier-tx Script error at input 0, got {error:?}"
    );
    Ok(())
}

#[test]
fn verify_block_transactions_rejects_cross_transaction_duplicate_spend()
-> Result<(), Box<dyn std::error::Error>> {
    let base_prevout = OutPoint::new(fixture_txid(0x64), 0);
    let utxo = utxo_with_output(base_prevout, 1)?;
    let handles = apply_handles(utxo);
    let first_spend = spending_transaction_to_script(base_prevout, u32::MAX, op_true_script());
    let second_spend = spending_transaction_to_script(base_prevout, u32::MAX - 1, op_true_script());
    let block = block_with_transactions(vec![first_spend, second_spend]);

    let error = match verify_block_transactions(
        &handles,
        &block,
        &mut bitcoin_rs_consensus::BlockView::new(&block.txs, block_txids(&block)),
        &tx_plan(&block),
        Arc::new(ResolvedUtxoView::resolve(
            handles.utxo.as_ref(),
            &block,
            &tx_plan(&block),
        )),
        &validation_context(&block, 2, 0, bitcoin_rs_script::VerifyFlags::NONE),
        BlockProvenance::Network,
        &kernel_block_of(&block),
    ) {
        Ok(()) => panic!("cross-transaction duplicate spend must fail script verification"),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        ApplyError::Consensus(bitcoin_rs_consensus::ConsensusError::MissingPrevout {
            input_index: 0
        })
    ));
    Ok(())
}

#[test]
fn verify_block_transactions_rejects_bad_coinbase_script_sig() {
    let mut coinbase = coinbase_transaction(0x63);
    coinbase.inputs[0].script_sig = Script::from_bytes(vec![0x63]);
    let block = block_with_transaction(coinbase);
    let handles = empty_apply_handles();

    let error = match verify_block_transactions(
        &handles,
        &block,
        &mut bitcoin_rs_consensus::BlockView::new(&block.txs, block_txids(&block)),
        &tx_plan(&block),
        Arc::new(ResolvedUtxoView::resolve(
            handles.utxo.as_ref(),
            &block,
            &tx_plan(&block),
        )),
        &validation_context(&block, 1, 0, bitcoin_rs_script::VerifyFlags::MANDATORY),
        BlockProvenance::Network,
        &kernel_block_of(&block),
    ) {
        Ok(()) => panic!("bad coinbase scriptSig length must fail transaction verification"),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        ApplyError::Consensus(
            bitcoin_rs_consensus::ConsensusError::CoinbaseScriptSigSize { len: 1 }
        )
    ));
}

#[test]
fn scripts_verified_upstream_follows_provenance() {
    let mut handles = empty_apply_handles();
    assert!(!handles.scripts_verified_upstream(BlockProvenance::Network, 1));
    assert!(handles.scripts_verified_upstream(BlockProvenance::LocalReplay, 1));

    handles.assume_valid_height = 10;
    handles.assume_valid_gate = Arc::new(AssumeValidGate::with_anchor(None));
    assert!(handles.scripts_verified_upstream(BlockProvenance::Network, 10));
    assert!(!handles.scripts_verified_upstream(BlockProvenance::Network, 11));
    assert!(handles.scripts_verified_upstream(BlockProvenance::LocalReplay, 11));
}

#[test]
fn verify_block_transactions_rejects_duplicate_spends_when_assume_valid_height_zero()
-> Result<(), Box<dyn std::error::Error>> {
    let (block, plan, utxo) = duplicate_spend_block()?;
    let handles = apply_handles_with_assume_valid(utxo, 0);

    let error = match verify_block_transactions(
        &handles,
        &block,
        &mut bitcoin_rs_consensus::BlockView::new(&block.txs, block_txids(&block)),
        &plan,
        Arc::new(ResolvedUtxoView::resolve(
            handles.utxo.as_ref(),
            &block,
            &plan,
        )),
        &validation_context(&block, 2, 0, bitcoin_rs_script::VerifyFlags::NONE),
        BlockProvenance::Network,
        &kernel_block_of(&block),
    ) {
        Ok(()) => panic!("duplicate spend must fail when assume_valid_height is zero"),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        ApplyError::Consensus(bitcoin_rs_consensus::ConsensusError::MissingPrevout {
            input_index: 0
        })
    ));
    Ok(())
}

#[test]
fn verify_block_transactions_rejects_duplicate_spends_within_assume_valid_height()
-> Result<(), Box<dyn std::error::Error>> {
    let (block, plan, utxo) = duplicate_spend_block()?;
    let handles = apply_handles_with_assume_valid(utxo, 2);

    let error = match verify_block_transactions(
        &handles,
        &block,
        &mut bitcoin_rs_consensus::BlockView::new(&block.txs, block_txids(&block)),
        &plan,
        Arc::new(ResolvedUtxoView::resolve(
            handles.utxo.as_ref(),
            &block,
            &plan,
        )),
        &validation_context(&block, 2, 0, bitcoin_rs_script::VerifyFlags::NONE),
        BlockProvenance::Network,
        &kernel_block_of(&block),
    ) {
        Ok(()) => panic!("duplicate spend must fail even under assume_valid_height"),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        ApplyError::Consensus(bitcoin_rs_consensus::ConsensusError::MissingPrevout {
            input_index: 0
        })
    ));
    Ok(())
}

#[test]
fn verify_block_transactions_rejects_duplicate_spends_above_assume_valid_height()
-> Result<(), Box<dyn std::error::Error>> {
    let (block, plan, utxo) = duplicate_spend_block()?;
    let handles = apply_handles_with_assume_valid(utxo, 2);

    let error = match verify_block_transactions(
        &handles,
        &block,
        &mut bitcoin_rs_consensus::BlockView::new(&block.txs, block_txids(&block)),
        &plan,
        Arc::new(ResolvedUtxoView::resolve(
            handles.utxo.as_ref(),
            &block,
            &plan,
        )),
        &validation_context(&block, 3, 0, bitcoin_rs_script::VerifyFlags::NONE),
        BlockProvenance::Network,
        &kernel_block_of(&block),
    ) {
        Ok(()) => panic!("duplicate spend must fail above assume_valid_height"),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        ApplyError::Consensus(bitcoin_rs_consensus::ConsensusError::MissingPrevout {
            input_index: 0
        })
    ));
    Ok(())
}

#[test]
fn verify_block_transactions_skips_script_execution_within_assume_valid_height()
-> Result<(), Box<dyn std::error::Error>> {
    let (block, plan, utxo) = bad_script_spend_block()?;
    let handles = apply_handles_with_assume_valid(utxo, 2);

    verify_block_transactions(
        &handles,
        &block,
        &mut bitcoin_rs_consensus::BlockView::new(&block.txs, block_txids(&block)),
        &plan,
        Arc::new(ResolvedUtxoView::resolve(
            handles.utxo.as_ref(),
            &block,
            &plan,
        )),
        &validation_context(&block, 2, 0, bitcoin_rs_script::VerifyFlags::MANDATORY),
        BlockProvenance::Network,
        &kernel_block_of(&block),
    )?;
    Ok(())
}

#[test]
fn verify_block_transactions_runs_script_checks_when_assume_valid_height_zero()
-> Result<(), Box<dyn std::error::Error>> {
    let (block, plan, utxo) = bad_script_spend_block()?;
    let handles = apply_handles_with_assume_valid(utxo, 0);

    let error = match verify_block_transactions(
        &handles,
        &block,
        &mut bitcoin_rs_consensus::BlockView::new(&block.txs, block_txids(&block)),
        &plan,
        Arc::new(ResolvedUtxoView::resolve(
            handles.utxo.as_ref(),
            &block,
            &plan,
        )),
        &validation_context(&block, 2, 0, bitcoin_rs_script::VerifyFlags::MANDATORY),
        BlockProvenance::Network,
        &kernel_block_of(&block),
    ) {
        Ok(()) => panic!("bad script must fail when assume_valid_height is zero"),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        ApplyError::Consensus(bitcoin_rs_consensus::ConsensusError::Script { input_index: 0, .. })
    ));
    Ok(())
}

#[test]
fn verify_block_transactions_runs_script_checks_above_assume_valid_height()
-> Result<(), Box<dyn std::error::Error>> {
    let (block, plan, utxo) = bad_script_spend_block()?;
    let handles = apply_handles_with_assume_valid(utxo, 2);

    let error = match verify_block_transactions(
        &handles,
        &block,
        &mut bitcoin_rs_consensus::BlockView::new(&block.txs, block_txids(&block)),
        &plan,
        Arc::new(ResolvedUtxoView::resolve(
            handles.utxo.as_ref(),
            &block,
            &plan,
        )),
        &validation_context(&block, 3, 0, bitcoin_rs_script::VerifyFlags::MANDATORY),
        BlockProvenance::Network,
        &kernel_block_of(&block),
    ) {
        Ok(()) => panic!("bad script must fail above assume_valid_height"),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        ApplyError::Consensus(bitcoin_rs_consensus::ConsensusError::Script { input_index: 0, .. })
    ));
    Ok(())
}

#[test]
fn verify_block_transactions_still_checks_coinbase_script_sig_under_assume_valid_height() {
    let mut coinbase = coinbase_transaction(0x63);
    coinbase.inputs[0].script_sig = Script::from_bytes(vec![0x63]);
    let block = block_with_transaction(coinbase);
    let mut handles = empty_apply_handles();
    handles.assume_valid_height = 100;

    let error = match verify_block_transactions(
        &handles,
        &block,
        &mut bitcoin_rs_consensus::BlockView::new(&block.txs, block_txids(&block)),
        &tx_plan(&block),
        Arc::new(ResolvedUtxoView::resolve(
            handles.utxo.as_ref(),
            &block,
            &tx_plan(&block),
        )),
        &validation_context(&block, 1, 0, bitcoin_rs_script::VerifyFlags::MANDATORY),
        BlockProvenance::Network,
        &kernel_block_of(&block),
    ) {
        Ok(()) => panic!("bad coinbase scriptSig length must fail under assume_valid_height"),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        ApplyError::Consensus(
            bitcoin_rs_consensus::ConsensusError::CoinbaseScriptSigSize { len: 1 }
        )
    ));
}

/// The live script-index predicate is this function's admission rule.
///
/// `bitcoin-rs-index` cannot depend on the consensus crate, so it carries
/// the script-size bound as its own literal. #225 requires the two
/// predicates to match exactly -- a divergence means the live view carries
/// locators no authoritative lookup can resolve, or drops coins that
/// exist -- and this assertion is where the duplication is held together.
#[test]
fn script_live_size_bound_matches_utxo_admission() {
    assert_eq!(
        bitcoin_rs_index::MAX_LIVE_SCRIPT_SIZE,
        bitcoin_rs_consensus::MAX_SCRIPT_SIZE,
        "the index's live predicate drifted from UTXO admission"
    );
}
