use super::*;

/// The allowance includes the fees the block actually earned.
///
/// A rule that only compared against the subsidy would pass the test above
/// and still be wrong in both directions: it would refuse every real block
/// that collects fees, and it would let a block claim fees it never earned.
#[test]
#[allow(clippy::arc_with_non_send_sync)]
fn the_coinbase_allowance_counts_the_fees_the_block_earned() {
    let subsidy =
        bitcoin_rs_consensus::block_subsidy(1, Network::Regtest.subsidy_halving_interval());
    // The seeded output is 1000 sats and the spend pays 1 sat onward.
    let fee = 999_u64;

    let exact = apply_block_with_a_fee_paying_transaction(subsidy + fee);
    assert!(
        exact.is_ok(),
        "the coinbase may claim the subsidy plus the fee it collected, got {exact:?}"
    );

    let over = apply_block_with_a_fee_paying_transaction(subsidy + fee + 1);
    assert!(
        matches!(
            &over,
            Err(ApplyError::Consensus(
                bitcoin_rs_consensus::ConsensusError::CoinbaseAmount { allowed, .. }
            )) if *allowed == subsidy + fee
        ),
        "one satoshi past the fee must be refused, got {over:?}"
    );
}

/// Proposal must run the same pre-write gates commit runs, including the
/// coinbase-amount check, and must not persist or publish a tip.
#[test]
#[allow(clippy::arc_with_non_send_sync)]
fn proposal_rejects_excess_coinbase_without_persisting() -> Result<(), Box<dyn std::error::Error>> {
    let subsidy =
        bitcoin_rs_consensus::block_subsidy(1, Network::Regtest.subsidy_halving_interval());
    let (handles, over) = height_one_prepared(vec![], subsidy + 1)?;
    let over_hash = Hash256::from(over.block_hash());
    let tip_before = handles
        .applied_tip
        .load_full()
        .unwrap_or_else(|| panic!("genesis tip missing before proposal"));
    let utxo_before = handles.utxo.len();

    let over_result = handles.validate_block(&over);
    assert!(
        matches!(
            &over_result,
            Err(ApplyError::Consensus(
                bitcoin_rs_consensus::ConsensusError::CoinbaseAmount { paid, allowed }
            )) if *paid == subsidy + 1 && *allowed == subsidy
        ),
        "proposal must refuse an over-subsidy coinbase, got {over_result:?}"
    );
    assert_eq!(
        handles
            .applied_tip
            .load_full()
            .as_deref()
            .map(|tip| tip.hash),
        Some(tip_before.hash),
        "a refused proposal must not move the applied tip"
    );
    assert_eq!(handles.utxo.len(), utxo_before);
    assert!(
        handles.undo_store.load_undo(1, over_hash)?.is_none(),
        "a refused proposal must not write an undo record"
    );

    let (handles, exact) = height_one_prepared(vec![], subsidy)?;
    let exact_hash = Hash256::from(exact.block_hash());
    handles.validate_block(&exact)?;
    assert_eq!(
        handles
            .applied_tip
            .load_full()
            .as_deref()
            .map(|tip| tip.hash),
        Some(Hash256::from(Network::Regtest.genesis_block().block_hash())),
        "an accepted proposal must not publish a new applied tip"
    );
    assert!(
        handles.undo_store.load_undo(1, exact_hash)?.is_none(),
        "an accepted proposal must not persist undo"
    );
    Ok(())
}

/// Timestamp rules must hold on the apply path, not only in header sync.
///
/// `applied_header_tip` inserts a header the tree has never seen, so before
/// this a caller handing `apply_block` a block directly could make one with
/// a timestamp at or below its parent's median-time-past the applied
/// consensus tip.
#[test]
#[allow(clippy::arc_with_non_send_sync)]
fn apply_rejects_a_block_whose_timestamp_precedes_its_parent()
-> Result<(), Box<dyn std::error::Error>> {
    let genesis = Network::Regtest.genesis_block();
    let utxo = Arc::new(UtxoSet::new());
    let handles = apply_handles_without_tx_index(Network::Regtest, Arc::clone(&utxo));
    let genesis_hash = Hash256::from(genesis.block_hash());
    let genesis_tip = applied_header_tip(&handles, genesis_hash, &genesis, 0)?;
    handles.applied_tip.store(Some(Arc::new(genesis_tip)));

    let mut block =
        block_with_prev_hash_and_transactions(genesis.block_hash(), vec![coinbase_transaction(1)]);
    // Exactly the parent's timestamp: the rule is strictly greater than the
    // median, and with one ancestor the median IS the parent's time.
    block.header.time = genesis.header.time;
    while !compact_is_met_by(block.header.bits, block.header.compute_hash().0) {
        block.header.nonce = block
            .header
            .nonce
            .checked_add(1)
            .ok_or_else(|| std::io::Error::other("test block nonce exhausted"))?;
    }
    let outcome = handles.apply_block(&block).map(|outcome| outcome.tip);

    assert!(
        matches!(
            &outcome,
            Err(ApplyError::Chain(
                bitcoin_rs_chain::ChainError::TimestampTooEarly { .. }
            ))
        ),
        "a block at or below its parent's median-time-past must be refused, got {outcome:?}"
    );

    // And it must be refused before anything is written. The check first
    // lived in `applied_header_tip`, which now runs BEFORE any mutation, so
    // the rejection left the block's outputs installed and later validation
    // could spend coins from a block outside the applied chain.
    assert_eq!(
        utxo.len(),
        0,
        "a refused block must leave no outputs in the UTXO set"
    );
    assert_eq!(
        handles
            .applied_tip
            .load()
            .as_ref()
            .map_or(u32::MAX, |tip| tip.height),
        0,
        "and must not move the tip"
    );
    Ok(())
}

/// A body that fails a cheap structural check must never reach the batch.
///
/// Batching made this a cost question, not just a correctness one: a peer
/// can keep the expected header and every txid while breaking the witness
/// commitment, and before the preflight that bought a full window of script
/// verification for a block rejected either way.
#[test]
#[allow(clippy::arc_with_non_send_sync)]
fn a_window_refuses_a_block_whose_merkle_root_does_not_match()
-> Result<(), Box<dyn std::error::Error>> {
    let genesis = Network::Regtest.genesis_block();
    let utxo = Arc::new(UtxoSet::new());
    let handles = apply_handles_for_network(Network::Regtest, Arc::clone(&utxo));
    let genesis_hash = Hash256::from(genesis.block_hash());
    let genesis_tip = applied_header_tip(&handles, genesis_hash, &genesis, 0)?;
    handles.applied_tip.store(Some(Arc::new(genesis_tip)));

    let block = mined_block_with_prev_hash_and_transactions(
        genesis.block_hash(),
        vec![coinbase_transaction(1)],
    )?;
    let block_hash = Hash256::from(block.block_hash());
    applied_header_tip(&handles, block_hash, &block, 1)?;
    let raw = bytes::Bytes::from(consensus_bytes(&block));
    assert_eq!(
        prove_window(&handles, &[&block], &[raw]).len(),
        1,
        "the honest block must prove, or this test proves nothing"
    );

    // Same header, different body: the merkle root no longer matches.
    let mut tampered = block.clone();
    tampered.txs.push(coinbase_transaction(2));
    assert_eq!(
        tampered.header, block.header,
        "the header must be untouched for this to be the attack described"
    );
    let raw = bytes::Bytes::from(consensus_bytes(&tampered));
    assert!(
        prove_window(&handles, &[&tampered], &[raw]).is_empty(),
        "a body that fails the merkle check must not reach the script batch"
    );
    Ok(())
}

#[test]
#[allow(clippy::arc_with_non_send_sync)]
fn a_window_never_proves_non_script_invalidity() -> Result<(), Box<dyn std::error::Error>> {
    #[derive(Clone, Copy, Debug)]
    enum Case {
        DuplicateInput,
        MissingPrevout,
        NonFinalLocktime,
        OutputsGreaterThanInputs,
        CoinbaseScriptSigLength,
        SigopOverflow,
    }

    for (index, case) in [
        Case::DuplicateInput,
        Case::MissingPrevout,
        Case::NonFinalLocktime,
        Case::OutputsGreaterThanInputs,
        Case::CoinbaseScriptSigLength,
        Case::SigopOverflow,
    ]
    .into_iter()
    .enumerate()
    {
        let prevout = OutPoint::new(fixture_txid(0x90 + u8::try_from(index)?), 0);
        let mut utxo = Arc::new(UtxoSet::new());
        let txdata = match case {
            Case::CoinbaseScriptSigLength => {
                let mut coinbase = coinbase_transaction(1);
                coinbase.inputs[0].script_sig = Script::from_bytes(vec![1]);
                vec![coinbase]
            }
            Case::SigopOverflow => {
                utxo = utxo_with_output(prevout, 0)?;
                let output_script =
                    vec![
                        0xac;
                        usize::try_from(bitcoin_rs_consensus::MAX_BLOCK_SIGOPS_COST / 4 + 1)?
                    ];
                let spend = spending_transaction_to_script(prevout, u32::MAX, output_script);
                vec![coinbase_transaction(1), spend]
            }
            _ => {
                if !matches!(case, Case::MissingPrevout) {
                    utxo = utxo_with_output(prevout, 0)?;
                }
                let mut spend = spending_transaction_to_script(prevout, u32::MAX, op_true_script());
                match case {
                    Case::DuplicateInput => spend.inputs.push(spend.inputs[0].clone()),
                    Case::MissingPrevout => {}
                    Case::NonFinalLocktime => {
                        spend.lock_time = LockTime::from_consensus(2);
                        spend.inputs[0].sequence = Sequence::from_consensus(0);
                    }
                    Case::OutputsGreaterThanInputs => {
                        spend.outputs[0].value = Amount::from_sat(2_000);
                    }
                    Case::CoinbaseScriptSigLength | Case::SigopOverflow => unreachable!(),
                }
                vec![coinbase_transaction(1), spend]
            }
        };
        let (handles, block, raw) = one_block_window_fixture(utxo, txdata, 0)?;
        assert!(
            prove_window(&handles, &[&block], &[raw]).is_empty(),
            "{case:?} must not produce a validation proof"
        );
    }
    Ok(())
}

/// The window must make the same assume-valid decision the single-block path
/// makes, and must not hand back script evidence for a block it skipped.
///
/// It used to do neither: every unit was prepared and executed before the
/// per-block decision was reached, so `--assume-valid-height N` did nothing
/// on the windowed path at all.
#[test]
#[allow(clippy::arc_with_non_send_sync)]
fn a_window_skips_scripts_for_assume_valid_blocks_and_proves_nothing_for_them()
-> Result<(), Box<dyn std::error::Error>> {
    let recorder = crate::metrics::test_recorder();

    let genesis = Network::Regtest.genesis_block();
    let prevout = OutPoint::new(fixture_txid(0x71), 0);

    // A spend that cannot pass: the prevout pays to a bare OP_EQUAL, so the
    // script fails whenever it actually runs. Whether the window ran it is
    // therefore observable in the result.
    let build = |assume_valid_height: u32| -> Result<_, Box<dyn std::error::Error>> {
        let utxo = Arc::new(UtxoSet::new());
        let mut changes = BlockChanges::default();
        changes.add(UtxoAdd::new(
            prevout,
            TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: Script::from_bytes(vec![0x87]),
            },
            false,
            0,
        ));
        utxo.commit_block(&changes, &Hash256::from_le_bytes(&[0x71; 32]))?;

        let mut handles = apply_handles_for_network(Network::Regtest, utxo);
        handles.assume_valid_height = assume_valid_height;
        let genesis_hash = Hash256::from(genesis.block_hash());
        let genesis_tip = applied_header_tip(&handles, genesis_hash, &genesis, 0)?;
        handles.applied_tip.store(Some(Arc::new(genesis_tip)));

        let spend = spending_transaction_to_script(prevout, u32::MAX, op_true_script());
        let block = mined_block_with_prev_hash_and_transactions(
            genesis.block_hash(),
            vec![coinbase_transaction(1), spend],
        )?;
        // The window refuses a block whose header the tree has not seen.
        // This test is about the assume-valid decision, not admission.
        let block_hash = Hash256::from(block.block_hash());
        applied_header_tip(&handles, block_hash, &block, 1)?;
        let raw = bytes::Bytes::from(consensus_bytes(&block));
        Ok((handles, block, raw))
    };

    // Height 1 is covered, and with no anchor pinned the gate is trusted.
    let (mut handles, block, raw) = build(100)?;
    let mut proven = metrics::with_local_recorder(&recorder, || {
        prove_window(&handles, &[&block], core::slice::from_ref(&raw))
    });
    assert_eq!(
        proven.len(),
        1,
        "a trusted block must not be failed by a script the window should never have run"
    );
    let Some(skipped) = proven.pop() else {
        panic!("window returned no entry for the only block");
    };
    assert!(
        matches!(skipped, ProvenApply::AssumeValidSkipped(_)),
        "a skipped block must carry AssumeValidSkipped, not script proof: the proof branch \
         bypasses the trust-gate re-read at commit, so a gate that flips in between would let \
         an unverified block through"
    );
    let mut entries = prove_window(&handles, &[&block], core::slice::from_ref(&raw));
    let Some(skipped) = entries.pop() else {
        panic!("the trusted assume-valid window returned one entry above");
    };
    handles.assume_valid_gate = Arc::new(AssumeValidGate::with_anchor(Some((
        1,
        Hash256::from_le_bytes(&[0xff; 32]),
    ))));
    assert!(!handles.assume_valid_gate.trusted());
    let transition = handles.lock_transition()?;
    let guard = handles.mempool_gateway.begin_chain_change()?;
    let proof = ChainChangeProof::new(transition, guard);
    let outcome = apply_committed_block_admitted(
        &handles,
        &block,
        Some(raw),
        Some(skipped),
        BlockProvenance::Network,
        &proof,
        super::super::window::PublishMode::Now,
    );
    assert!(
        matches!(
            outcome,
            Err(ApplyError::Consensus(
                bitcoin_rs_consensus::ConsensusError::Script { input_index: 0, .. }
            ))
        ),
        "trust-gate flip must re-enter ordinary script validation, got {outcome:?}"
    );

    // Full verification must be completely unaffected.
    let (handles, block, raw) = build(0)?;
    let proven = prove_window(&handles, &[&block], &[raw]);
    assert!(
        proven.is_empty(),
        "with assume_valid_height 0 the bad script must still fail the window"
    );
    Ok(())
}

/// Preserved bytes must be the block, not a block with the same shape.
///
/// The witness is the hole a count check leaves open: changing it does not
/// change any txid, so the decoded block and the bytes can disagree on
/// exactly the data script verification reads while every count and every
/// txid still matches.
#[test]
fn preserved_bytes_carrying_a_different_witness_are_rejected()
-> Result<(), Box<dyn std::error::Error>> {
    let genesis = Network::Regtest.genesis_block();
    let mut block = mined_block_with_prev_hash_and_transactions(
        genesis.block_hash(),
        vec![coinbase_transaction(1)],
    )?;

    let honest = bytes::Bytes::from(consensus_bytes(&block));
    assert!(
        bytes_are_block(&honest, &block),
        "the block's own serialization must be accepted"
    );

    // Swap only the witness. Every txid, the transaction count, and the
    // header are untouched.
    let before = block.txs.iter().map(Tx::txid).collect::<Vec<_>>();
    let Some(input) = block.txs.first_mut().and_then(|tx| tx.inputs.first_mut()) else {
        panic!("coinbase has no input");
    };
    input.witness.push(vec![0xab_u8; 32]);
    let after = block.txs.iter().map(Tx::txid).collect::<Vec<_>>();
    assert_eq!(
        before, after,
        "the witness swap must not move a txid, or this proves nothing"
    );

    assert!(
        !bytes_are_block(&honest, &block),
        "bytes whose witness differs from the block must be rejected"
    );
    let outcome = parse_block_for_apply(&block, Some(honest));
    assert!(
        outcome.is_err(),
        "apply must refuse a block whose preserved bytes are not its serialization"
    );
    Ok(())
}
