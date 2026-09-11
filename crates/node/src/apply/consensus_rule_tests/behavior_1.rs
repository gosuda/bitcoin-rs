use super::*;

#[test]
fn applied_record_carries_block_metadata_without_the_body() {
    let block = block_with_transaction(coinbase_transaction(0x42));
    let block_hash = block.block_hash();
    let record = bitcoin_rs_rpc::context::BlockRecord::from_block(7, &block);

    assert_eq!(record.hash, block_hash);
    assert_eq!(record.height, 7);
    assert_eq!(record.body_size, consensus_bytes(&block).len());
    assert!(record.header.is_none());
    assert_eq!(record.tx_count, block.txs.len());
    assert_eq!(record.time, block.header.time);
}

#[test]
fn verify_block_transactions_accepts_same_block_spend() -> Result<(), Box<dyn std::error::Error>> {
    let base_prevout = OutPoint::new(fixture_txid(0x61), 0);
    let utxo = utxo_with_output(base_prevout, 1)?;
    let handles = apply_handles(utxo);
    let funding_tx = spending_transaction_to_script(base_prevout, u32::MAX, op_true_script());
    let funding_outpoint = OutPoint::new(funding_tx.txid(), 0);
    let same_block_spend =
        spending_transaction_to_script(funding_outpoint, u32::MAX, op_true_script());
    let block = block_with_transactions(vec![funding_tx, same_block_spend]);

    verify_block_transactions(
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
    )?;
    Ok(())
}

#[test]
fn block_local_utxo_view_resolves_earlier_same_block_output() -> Result<(), ApplyError> {
    let created = coinbase_transaction(0x41);
    let outpoint = OutPoint::new(created.txid(), 0);
    let spending = spending_transaction_to_script(outpoint, u32::MAX, op_true_script());
    let block = block_with_transactions(vec![created, spending]);
    let mut view = BlockLocalUtxoView::new(Arc::new(ResolvedUtxoView::empty()), &block.txs, 42, 2);

    view.add_outputs(0, block.txs[0].txid(), block.txs[0].outputs.len())?;
    let resolved = view.lookup(&outpoint);

    let output = resolved.ok_or(ApplyError::HeightOverflow(42))?;
    assert_eq!(output.value, block.txs[0].outputs[0].value);
    assert_eq!(output.script_pubkey, block.txs[0].outputs[0].script_pubkey);
    Ok(())
}

#[test]
fn block_local_utxo_view_hides_same_block_double_spend() -> Result<(), ApplyError> {
    let created = coinbase_transaction(0x42);
    let outpoint = OutPoint::new(created.txid(), 0);
    let first_spend = spending_transaction_to_script(outpoint, u32::MAX, op_true_script());
    let second_spend = spending_transaction_to_script(outpoint, u32::MAX, op_true_script());
    let block = block_with_transactions(vec![created, first_spend, second_spend]);
    let mut view = BlockLocalUtxoView::new(Arc::new(ResolvedUtxoView::empty()), &block.txs, 42, 3);

    view.add_outputs(0, block.txs[0].txid(), block.txs[0].outputs.len())?;
    assert!(view.lookup(&outpoint).is_some());
    view.spend_inputs(&block.txs[1]);

    assert_eq!(view.lookup(&outpoint), None);
    Ok(())
}

#[test]
fn block_local_utxo_view_create_after_spend_uses_last_write() -> Result<(), ApplyError> {
    let created = coinbase_transaction(0x43);
    let outpoint = OutPoint::new(created.txid(), 0);
    let spending = spending_transaction_to_script(outpoint, u32::MAX, op_true_script());
    let block = block_with_transactions(vec![spending, created]);
    let mut view = BlockLocalUtxoView::new(Arc::new(ResolvedUtxoView::empty()), &block.txs, 42, 2);

    view.spend_inputs(&block.txs[0]);
    view.add_outputs(1, block.txs[1].txid(), block.txs[1].outputs.len())?;

    assert_eq!(
        view.lookup(&outpoint),
        Some(block.txs[1].outputs[0].clone())
    );
    Ok(())
}

#[test]
fn block_local_utxo_view_hides_later_same_block_output() -> Result<(), ApplyError> {
    let earlier = coinbase_transaction(0x44);
    let later = coinbase_transaction(0x45);
    let later_outpoint = OutPoint::new(later.txid(), 0);
    let block = block_with_transactions(vec![earlier, later]);
    let mut view = BlockLocalUtxoView::new(Arc::new(ResolvedUtxoView::empty()), &block.txs, 42, 2);

    view.add_outputs(0, block.txs[0].txid(), block.txs[0].outputs.len())?;

    assert_eq!(view.lookup(&later_outpoint), None);
    Ok(())
}

/// R2 pin (shared-view parallel path): under the kernel feature the script
/// verdict carries the kernel dispatch marker — the Rust interpreter did
/// not produce it.
#[test]
#[cfg(feature = "kernel")]
fn verify_block_transactions_shared_view_path_uses_kernel_verdict()
-> Result<(), Box<dyn std::error::Error>> {
    let (block, plan, utxo) = bad_script_spend_block()?;
    let handles = apply_handles(utxo);

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
        Ok(()) => panic!("bad script must fail under the kernel build"),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        ApplyError::Consensus(bitcoin_rs_consensus::ConsensusError::Script {
            input_index: 0,
            ref reason,
        }) if reason.starts_with("kernel script verification failed:")
    ));
    Ok(())
}

/// R2 pin (overlay path): a same-block spend resolved against the frozen
/// per-tx snapshot view is also verdict-checked by the kernel.
#[test]
#[cfg(feature = "kernel")]
fn verify_block_transactions_overlay_path_uses_kernel_verdict()
-> Result<(), Box<dyn std::error::Error>> {
    let base_prevout = OutPoint::new(fixture_txid(0x67), 0);
    let utxo = utxo_with_output(base_prevout, 1)?;
    let handles = apply_handles(utxo);
    let funding_tx = spending_transaction_to_script(base_prevout, u32::MAX, vec![0x87]);
    let funding_outpoint = OutPoint::new(funding_tx.txid(), 0);
    let mut script_sig = push_int(7);
    script_sig.extend_from_slice(&push_int(8));
    let bad_same_block_spend = Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: funding_outpoint,
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
    let block = block_with_transactions(vec![funding_tx, bad_same_block_spend]);
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
        Ok(()) => panic!("bad same-block spend must fail under the kernel build"),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        ApplyError::Consensus(bitcoin_rs_consensus::ConsensusError::Script {
            input_index: 0,
            ref reason,
        }) if reason.starts_with("kernel script verification failed:")
    ));
    Ok(())
}

#[test]
fn assume_valid_gate_new_pins_only_the_exact_anchor_height() {
    let anchor_height = Network::Mainnet
        .assume_valid_anchor()
        .map_or(0, |(height, _)| height);
    assert!(anchor_height > 0);

    let no_pin = AssumeValidGate::new(Network::Mainnet, 0);
    assert!(no_pin.trusted(), "zero configured height means no pin");

    let pinned = AssumeValidGate::new(Network::Mainnet, anchor_height);
    assert!(
        !pinned.trusted(),
        "exact anchor height starts untrusted until the chain is evaluated"
    );

    let off_by_one = AssumeValidGate::new(Network::Mainnet, anchor_height + 1);
    assert!(
        off_by_one.trusted(),
        "custom heights keep the height-only shortcut without a pin"
    );

    let unanchored = AssumeValidGate::with_anchor(None);
    assert!(unanchored.trusted(), "no anchor means always trusted");
}

#[test]
fn assume_valid_gate_evaluate_trusts_only_the_chain_containing_the_anchor()
-> Result<(), Box<dyn std::error::Error>> {
    let handles = empty_apply_handles();
    let bits = 0x207f_ffff;
    let headers: Vec<_> = (0..=4).map(|height| (bits, height)).collect();
    seed_pow_chain_with_headers(&handles, &headers)?;

    let anchor_hash = {
        let tree = handles.block_tree.read();
        let tip = tree
            .tip()
            .ok_or_else(|| std::io::Error::other("missing tip"))?;
        let anchor_id = tree
            .node_at_height_from(tip.tip_id, 2)
            .ok_or_else(|| std::io::Error::other("missing anchor node"))?;
        tree.node(anchor_id)?.hash
    };

    let pinned = AssumeValidGate::with_anchor(Some((2, anchor_hash)));
    assert!(!pinned.trusted(), "pinned gate starts untrusted");
    {
        let tree = handles.block_tree.read();
        pinned.evaluate(&tree);
    }
    assert!(
        pinned.trusted(),
        "active chain contains the anchor block, so the gate must trust it"
    );

    let diverged = AssumeValidGate::with_anchor(Some((2, Hash256::from_le_bytes(&[0xee; 32]))));
    {
        let tree = handles.block_tree.read();
        diverged.evaluate(&tree);
    }
    assert!(
        !diverged.trusted(),
        "a chain lacking the pinned hash must never be trusted"
    );
    {
        let tree = handles.block_tree.read();
        diverged.evaluate(&tree);
    }
    assert!(
        !diverged.trusted(),
        "re-evaluation on the same diverged chain keeps the gate untrusted"
    );
    Ok(())
}

#[test]
fn verify_block_transactions_rejects_excess_output_value_under_assume_valid_height()
-> Result<(), Box<dyn std::error::Error>> {
    // Skipping script checks must NOT skip the input/output value-balance check:
    // a transaction whose outputs exceed its inputs is rejected even within
    // assume_valid_height.
    let (block, plan, utxo) = excess_value_spend_block()?;
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
        &validation_context(&block, 2, 0, bitcoin_rs_script::VerifyFlags::MANDATORY),
        BlockProvenance::Network,
        &kernel_block_of(&block),
    ) {
        Ok(()) => panic!("outputs exceeding inputs must fail even under assume_valid_height"),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        ApplyError::Consensus(
            bitcoin_rs_consensus::ConsensusError::InputsLessThanOutputs {
                input_value: 1_000,
                output_value: 2_000,
            }
        )
    ));
    Ok(())
}

#[test]
fn build_utxo_changes_excludes_op_return_outputs() -> Result<(), Box<dyn std::error::Error>> {
    let mut coinbase = coinbase_transaction(0x6f);
    coinbase.outputs.push(TxOut {
        value: Amount::from_sat(0),
        script_pubkey: Script::from_bytes(op_return_script(b"not a coin")),
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

    utxo.commit_borrowed_block(&changes, &Hash256::from_le_bytes(&[0x72; 32]))?;

    assert!(utxo.get(&OutPoint::new(txid, 0)).is_some());
    assert!(utxo.get(&OutPoint::new(txid, 1)).is_none());
    Ok(())
}

#[test]
#[allow(clippy::arc_with_non_send_sync)]
fn build_utxo_changes_nets_same_block_created_then_spent_outputs()
-> Result<(), Box<dyn std::error::Error>> {
    let base_prevout = OutPoint::new(fixture_txid(0x62), 0);
    let utxo = utxo_with_output(base_prevout, 1)?;
    let funding_tx = spending_transaction_to_script(base_prevout, u32::MAX, op_true_script());
    let funding_outpoint = OutPoint::new(funding_tx.txid(), 0);
    let same_block_spend =
        spending_transaction_to_script(funding_outpoint, u32::MAX, op_true_script());
    let final_outpoint = OutPoint::new(same_block_spend.txid(), 0);
    let block = block_with_transactions(vec![funding_tx, same_block_spend]);

    let scratch = ApplyScratch::new(&block, false);
    // The block spends an external prevout, so the undo half needs the
    // resolved view that spend came from. An empty view would now be
    // rejected, which is the point of UndoPrevoutMissing.
    let resolved = ResolvedUtxoView::resolve(utxo.as_ref(), &block, &tx_plan(&block));
    let (add_cap, rem_cap) = scratch.utxo_change_capacity();
    let (changes, undo, _totals) = build_block_changes(
        &block,
        2,
        scratch.txids(),
        scratch.same_block_spent(),
        add_cap,
        rem_cap,
        &resolved,
        None,
        MAX_SCRIPT_SIZE,
    )?;
    assert_eq!(
        undo.restores().len(),
        1,
        "only the external spend is restorable; the same-block spend never entered the set"
    );
    utxo.commit_borrowed_block(&changes, &Hash256::from_le_bytes(&[0x63; 32]))?;

    assert!(utxo.get(&base_prevout).is_none());
    assert!(utxo.get(&funding_outpoint).is_none());
    assert!(utxo.get(&final_outpoint).is_some());
    Ok(())
}

#[test]
fn apply_scratch_omits_rawtx_bytes_when_not_requested() {
    let block = block_with_transactions(vec![coinbase_transaction(0x71), transaction(0x72)]);

    let scratch = ApplyScratch::new(&block, false);

    assert_eq!(scratch.txids().len(), block.txs.len());
    assert!(scratch.raw_txs().is_none());
}

#[test]
fn apply_scratch_keeps_rawtx_bytes_when_requested() -> Result<(), Box<dyn std::error::Error>> {
    let block = block_with_transactions(vec![coinbase_transaction(0x73), transaction(0x74)]);

    let scratch = ApplyScratch::new(&block, true);
    let raw_txs = scratch
        .raw_txs()
        .ok_or_else(|| std::io::Error::other("rawtx bytes missing"))?;

    assert_eq!(raw_txs.len(), block.txs.len());
    assert_eq!(raw_txs[0], consensus_bytes(&block.txs[0]));
    Ok(())
}

#[test]
fn daa_non_retarget_height_requires_parent_bits() -> Result<(), Box<dyn std::error::Error>> {
    let handles = empty_apply_handles();
    let parent_hash = seed_pow_chain(
        &handles,
        MAINNET_POW_LIMIT_BITS,
        DAA_ANCHOR_TIME,
        DAA_ANCHOR_TIME + 600,
        1,
    )?;
    let block = block_with_pow_header(
        parent_hash,
        MAINNET_POW_LIMIT_DIV_4_BITS,
        DAA_ANCHOR_TIME + 1_200,
        2,
    );

    let error = match check_pow_limit_and_continuity_for_seeded_tip(&handles, &block, 2) {
        Ok(()) => panic!("non-retarget height must inherit parent nBits"),
        Err(error) => error,
    };
    assert_nbits_error(
        &error,
        MAINNET_POW_LIMIT_DIV_4_BITS,
        MAINNET_POW_LIMIT_BITS,
        2,
    );
    Ok(())
}
