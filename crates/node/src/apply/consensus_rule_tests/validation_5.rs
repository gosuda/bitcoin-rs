use super::*;

/// At a BIP30 exception height the coinbase reuses a txid whose outputs are
/// still live, so the add overwrites a coin rather than creating one. The
/// undo must put the overwritten coin back; removing the new output instead
/// loses the old one for good and the rewound set no longer matches the
/// parent.
#[test]
#[allow(clippy::arc_with_non_send_sync)]
fn bip30_exception_undo_restores_the_coin_it_overwrote() -> Result<(), Box<dyn std::error::Error>> {
    let utxo = Arc::new(UtxoSet::new());
    let block = block_with_transactions(vec![coinbase_transaction(7)]);
    let coinbase = block.txs.first().ok_or("block has no coinbase")?;
    let reused = OutPoint::new(coinbase.txid(), 0);

    // The older coin at the very same outpoint, with values the new one does
    // not share, so a restore that invents a coin cannot pass.
    let older = TxOut {
        value: Amount::from_sat(4_242),
        script_pubkey: Script::from_bytes(op_true_script()),
    };
    let mut seed = bitcoin_rs_utxo::BlockChanges::default();
    seed.add(bitcoin_rs_utxo::UtxoAdd::new(
        reused,
        older.clone(),
        true,
        91_722,
    ));
    utxo.commit_block(&seed, &Hash256::from_le_bytes(&[0x30; 32]))?;

    let scratch = ApplyScratch::new(&block, false);
    let (add_cap, rem_cap) = scratch.utxo_change_capacity();
    let (_changes, undo, _totals) = build_block_changes(
        &block,
        91_842,
        scratch.txids(),
        scratch.same_block_spent(),
        add_cap,
        rem_cap,
        &ResolvedUtxoView::empty(),
        Some(utxo.as_ref()),
        MAX_SCRIPT_SIZE,
    )?;

    assert!(
        undo.removes().is_empty(),
        "an overwrite is undone by writing the old coin back, not by deleting the outpoint"
    );
    let restored = undo
        .restores()
        .iter()
        .find(|entry| entry.outpoint == reused)
        .ok_or("undo does not restore the overwritten coin")?;
    assert_eq!(restored.txout, older, "the ORIGINAL output must come back");
    assert_eq!(restored.height, 91_722, "at its original height");
    assert!(restored.coinbase, "and with its original coinbase flag");
    Ok(())
}

/// The header hash names the block; it does not vouch for the transactions
/// handed over with it. A duplicate final transaction on an odd-width Merkle
/// level preserves the ordinary root, so disconnect must use the
/// mutation-aware verifier before touching any state.
#[test]
#[allow(clippy::arc_with_non_send_sync, clippy::too_many_lines)]
fn disconnect_refuses_duplicate_last_transaction_merkle_mutation()
-> Result<(), Box<dyn std::error::Error>> {
    let genesis = Network::Regtest.genesis_block();
    let external_prevout = OutPoint::new(fixture_txid(0x92), 0);
    let utxo = utxo_with_output(external_prevout, 1)?;
    let handles = apply_handles_without_tx_index(Network::Regtest, Arc::clone(&utxo));
    let genesis_hash = Hash256::from(genesis.block_hash());
    let genesis_tip = applied_header_tip(&handles, genesis_hash, &genesis, 0)?;
    handles.applied_tip.store(Some(Arc::new(genesis_tip)));

    let funding_tx = spending_transaction_to_script(external_prevout, u32::MAX, op_true_script());
    let funding_outpoint = OutPoint::new(funding_tx.txid(), 0);
    let same_block_spend =
        spending_transaction_to_script(funding_outpoint, u32::MAX, op_true_script());
    let block = mined_block_with_prev_hash_and_transactions(
        genesis.block_hash(),
        vec![
            coinbase_transaction(1),
            funding_tx,
            same_block_spend.clone(),
        ],
    )?;
    let applied = handles.apply_block(&block)?.tip;
    let outputs_before = utxo.len();
    let tree_tip_before = handles
        .block_tree
        .read()
        .tip()
        .map(|tip| (tip.tip_id, tip.height, tip.hash));
    let marker_before = handles.undo_store.load_disconnect_marker()?;

    let mut mutated = block.clone();
    mutated.txs.push(same_block_spend);
    assert_eq!(
        txids_merkle_root(&mutated),
        Some(block.header.merkle_root),
        "duplicate-last mutation must preserve the ordinary Merkle root"
    );
    assert!(
        txids_merkle_root(&mutated) == Some(mutated.header.merkle_root),
        "the ordinary Merkle check must accept this mutation, or the test is only the old mismatch guard"
    );
    assert_eq!(
        mutated.block_hash(),
        block.block_hash(),
        "the mutated body must retain the applied header and block hash"
    );

    let outcome = handles
        .disconnect_block(&mutated)
        .map(|outcome| outcome.parent_tip);

    assert!(
        matches!(
            &outcome,
            Err(crate::DisconnectError::Refused(boxed))
                if matches!(**boxed, ApplyError::DisconnectBodyMismatch { hash } if hash == applied.hash)
        ),
        "a mutation hidden from the ordinary root must be refused, got {outcome:?}"
    );
    assert_eq!(
        utxo.len(),
        outputs_before,
        "a refused disconnect must not touch the UTXO set"
    );
    assert_eq!(
        handles
            .applied_tip
            .load_full()
            .map(|tip| (tip.height, tip.hash)),
        Some((applied.height, applied.hash)),
        "a refused disconnect must leave the applied tip unchanged"
    );
    assert_eq!(
        handles
            .block_tree
            .read()
            .tip()
            .map(|tip| (tip.tip_id, tip.height, tip.hash)),
        tree_tip_before,
        "a refused disconnect must leave the active header index unchanged"
    );
    assert_eq!(
        handles.undo_store.load_disconnect_marker()?,
        marker_before,
        "mutation refusal must happen before the disconnect marker is armed"
    );
    Ok(())
}

#[test]
fn apply_block_rejects_same_block_coinbase_spend() -> Result<(), Box<dyn std::error::Error>> {
    let genesis = Network::Regtest.genesis_block();
    let handles = apply_handles_without_tx_index(Network::Regtest, empty_utxo());
    let genesis_tip =
        applied_header_tip(&handles, Hash256::from(genesis.block_hash()), &genesis, 0)?;
    handles.applied_tip.store(Some(Arc::new(genesis_tip)));

    let mut coinbase = coinbase_transaction(0x94);
    coinbase.outputs[0].script_pubkey = Script::from_bytes(op_true_script());
    let coinbase_outpoint = OutPoint::new(coinbase.txid(), 0);
    let spend = spending_transaction_to_script(coinbase_outpoint, u32::MAX, op_true_script());
    let block =
        mined_block_with_prev_hash_and_transactions(genesis.block_hash(), vec![coinbase, spend])?;

    let error = match handles.apply_block(&block).map(|outcome| outcome.tip) {
        Ok(_) => panic!("same-block coinbase spend must fail the apply"),
        Err(error) => error,
    };

    assert_bip_error(&error, "COINBASE_MATURITY");
    Ok(())
}

#[test]
fn apply_block_rejects_future_same_block_prevout_without_utxo_commit()
-> Result<(), Box<dyn std::error::Error>> {
    let genesis = Network::Regtest.genesis_block();
    let external_prevout = OutPoint::new(fixture_txid(0x95), 0);
    let handles =
        apply_handles_without_tx_index(Network::Regtest, utxo_with_output(external_prevout, 1)?);
    let genesis_tip =
        applied_header_tip(&handles, Hash256::from(genesis.block_hash()), &genesis, 0)?;
    handles.applied_tip.store(Some(Arc::new(genesis_tip)));

    let later_tx = spending_transaction_to_script(external_prevout, u32::MAX, op_true_script());
    let future_prevout = OutPoint::new(later_tx.txid(), 0);
    let premature_spend =
        spending_transaction_to_script(future_prevout, u32::MAX, op_true_script());
    let block = mined_block_with_prev_hash_and_transactions(
        genesis.block_hash(),
        vec![coinbase_transaction(0x95), premature_spend, later_tx],
    )?;

    let error = match handles.apply_block(&block).map(|outcome| outcome.tip) {
        Ok(_) => {
            panic!("future same-block prevout must fail before scratch-backed side effects")
        }
        Err(error) => error,
    };

    assert!(matches!(error, ApplyError::Consensus(_)));
    assert!(handles.utxo.get(&future_prevout).is_none());
    Ok(())
}

// Asserts acceptance under the BIP16 exception, which needs a real script backend
// (the backend-less default build returns a "backend disabled" Script error).
#[cfg(feature = "kernel")]
#[test]
fn bip16_exception_accepts_bare_p2sh_template_spend_that_normal_p2sh_rejects()
-> Result<(), Box<dyn std::error::Error>> {
    // Parse the exception-block hash from its display hex so a byte-order
    // flip against the stored consensus-LE constant cannot drift, and take
    // a non-exception sibling hash.
    let exception_hash = Hash256::from(
        "00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22".parse::<BlockHash>()?,
    );
    let normal_hash = Hash256::from_le_bytes(&[0x11; 32]); // any non-exception block

    // csv + segwit inactive: height 170060 predates both softforks.
    let softforks = bitcoin_rs_chain::SoftforkState {
        csv_active: false,
        segwit_active: false,
    };

    // At height 170060 the only height-gated flag is P2SH, so:
    //   exception block -> compute_verify_flags drops P2SH
    //   normal block    -> compute_verify_flags carries P2SH
    let exc_flags = compute_verify_flags(Network::Mainnet, 170_060, exception_hash, softforks);
    let normal_flags = compute_verify_flags(Network::Mainnet, 170_060, normal_hash, softforks);
    assert!(!exc_flags.contains(bitcoin_rs_script::VerifyFlags::P2SH));
    assert!(normal_flags.contains(bitcoin_rs_script::VerifyFlags::P2SH));

    // Exception block: bare-valid P2SH-template spend is ACCEPTED.
    let (block, plan, utxo) = p2sh_template_bare_spend_block()?;
    let handles = apply_handles_with_assume_valid(utxo, 0); // full verification
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
        &validation_context(&block, 170_060, 0, exc_flags),
        BlockProvenance::Network,
        &kernel_block_of(&block),
    )?;

    // Normal block at the same height: P2SH enforced -> REJECTED at input 0.
    let (block2, plan2, utxo2) = p2sh_template_bare_spend_block()?;
    let handles2 = apply_handles_with_assume_valid(utxo2, 0);
    let err = match verify_block_transactions(
        &handles2,
        &block2,
        &mut bitcoin_rs_consensus::BlockView::new(&block2.txs, block_txids(&block2)),
        &plan2,
        Arc::new(ResolvedUtxoView::resolve(
            handles2.utxo.as_ref(),
            &block2,
            &plan2,
        )),
        &validation_context(&block2, 170_060, 0, normal_flags),
        BlockProvenance::Network,
        &kernel_block_of(&block2),
    ) {
        Ok(()) => {
            panic!("normal P2SH enforcement must reject the bare-script redeem spend")
        }
        Err(e) => e,
    };
    assert!(matches!(
        err,
        ApplyError::Consensus(bitcoin_rs_consensus::ConsensusError::Script { input_index: 0, .. })
    ));
    Ok(())
}

/// #618 regression: a kernel-backed script verification failure must be
/// classified Operational (retryable), not Permanent, because
/// `bitcoinkernel` can reject a valid block depending on process state.
/// The same block applies successfully after restart, so permanently
/// invalidating its header subtree would freeze the node at the tip.
#[test]
fn kernel_script_verification_failure_is_operational() {
    let error = ApplyError::Consensus(bitcoin_rs_consensus::ConsensusError::Script {
        input_index: 0,
        reason: "kernel script verification failed: Script verification failed".to_owned(),
    });
    assert!(
        !is_permanent_apply_error(&error),
        "kernel script verification failures must be Operational (retryable) per #618"
    );
}

/// A native (non-kernel) script verification failure remains Permanent:
/// the native interpreter is deterministic and not process-state-dependent.
#[test]
fn native_script_verification_failure_is_permanent() {
    let error = ApplyError::Consensus(bitcoin_rs_consensus::ConsensusError::Script {
        input_index: 0,
        reason: "Script verification failed".to_owned(),
    });
    assert!(
        is_permanent_apply_error(&error),
        "native script verification failures must remain Permanent"
    );
}
