//! Difficulty-adjustment behavior is governed by
//! `docs/contracts/consensus-difficulty.md` (`DAA-01`), against the pinned
//! Bitcoin Core 31.1 reference (`docs/contracts/reference-set.md`, `REF-02`).

use super::*;

/// BIP22 proposal omits the self-consistency `PoW` check that commit enforces.
#[test]
#[allow(clippy::arc_with_non_send_sync)]
fn proposal_omits_proof_of_work() -> Result<(), Box<dyn std::error::Error>> {
    let subsidy =
        bitcoin_rs_consensus::block_subsidy(1, Network::Regtest.subsidy_halving_interval());
    let (handles, mut block) = height_one_prepared(vec![], subsidy)?;
    while compact_is_met_by(block.header.bits, block.header.compute_hash().0) {
        block.header.nonce = block
            .header
            .nonce
            .checked_add(1)
            .ok_or_else(|| std::io::Error::other("test block nonce exhausted"))?;
    }
    handles.validate_block(&block)?;
    let commit = handles.apply_block(&block).map(|outcome| outcome.tip);
    assert!(
        matches!(commit, Err(ApplyError::ProofOfWork { .. })),
        "commit must still refuse unsolved PoW, got {commit:?}"
    );
    Ok(())
}

#[test]
#[allow(clippy::arc_with_non_send_sync)]
fn every_validation_context_mismatch_rebuilds_from_live_utxo()
-> Result<(), Box<dyn std::error::Error>> {
    #[derive(Clone, Copy, Debug)]
    enum Field {
        Hash,
        Parent,
        Height,
        Flags,
        LocktimeCutoff,
    }

    for field in [
        Field::Hash,
        Field::Parent,
        Field::Height,
        Field::Flags,
        Field::LocktimeCutoff,
    ] {
        let prevout = OutPoint::new(fixture_txid(0x72), 0);
        let utxo = utxo_with_output(prevout, 0)?;
        let spend = spending_transaction_to_script(prevout, u32::MAX, op_true_script());
        let (handles, block, raw) =
            one_block_window_fixture(Arc::clone(&utxo), vec![coinbase_transaction(1), spend], 0)?;
        let mut entries = prove_window(&handles, &[&block], core::slice::from_ref(&raw));
        let Some(ProvenApply::Proven(mut proof)) = entries.pop() else {
            panic!("valid fixture did not produce a proof for {field:?}");
        };

        match field {
            Field::Hash => proof.context.hash = Hash256::from_le_bytes(&[0x81; 32]),
            Field::Parent => proof.context.parent = Hash256::from_le_bytes(&[0x82; 32]),
            Field::Height => proof.context.height = proof.context.height.saturating_add(1),
            Field::Flags => {
                proof.context.flags = if proof.context.flags == bitcoin_rs_script::VerifyFlags::NONE
                {
                    bitcoin_rs_script::VerifyFlags::MANDATORY
                } else {
                    bitcoin_rs_script::VerifyFlags::NONE
                };
            }
            Field::LocktimeCutoff => {
                proof.context.locktime_cutoff = proof.context.locktime_cutoff.saturating_add(1);
            }
        }

        let mut remove = BlockChanges::default();
        remove.remove(prevout);
        utxo.commit_block(&remove, &Hash256::from_le_bytes(&[0x83; 32]))?;

        let transition = handles.lock_transition()?;
        let guard = handles.mempool_gateway.begin_chain_change()?;
        let chain_proof = ChainChangeProof::new(transition, guard);
        let Err(error) = apply_committed_block_admitted(
            &handles,
            &block,
            Some(raw),
            Some(ProvenApply::Proven(proof)),
            BlockProvenance::Network,
            &chain_proof,
            super::super::window::PublishMode::Now,
        ) else {
            panic!("a mismatched proof must re-read the now-missing live prevout");
        };
        assert!(
            matches!(
                error,
                ApplyError::Consensus(bitcoin_rs_consensus::ConsensusError::MissingPrevout {
                    input_index: 0
                })
            ),
            "{field:?} mismatch used stale prepared state instead of ordinary validation: {error:?}"
        );
    }
    Ok(())
}

/// Two connects racing for the same height must produce one winner and one
/// rejection, never two blocks that both believe they extended the tip.
///
/// Before the transition lock this could pass both: `ApplyAdmission::enter`
/// hands out read guards, so both threads cleared the predecessor check
/// against the same tip and then raced to publish, and whichever published
/// second silently discarded the other's block.
#[test]
#[allow(clippy::arc_with_non_send_sync)]
fn two_concurrent_connects_at_one_height_produce_one_winner()
-> Result<(), Box<dyn std::error::Error>> {
    let genesis = Network::Regtest.genesis_block();
    let utxo = Arc::new(UtxoSet::new());
    let handles = apply_handles_without_tx_index(Network::Regtest, Arc::clone(&utxo));
    let genesis_hash = Hash256::from(genesis.block_hash());
    let genesis_tip = applied_header_tip(&handles, genesis_hash, &genesis, 0)?;
    handles.applied_tip.store(Some(Arc::new(genesis_tip)));

    // Two distinct children of the same parent: both are valid extensions of
    // the current tip, and exactly one may become it.
    let left = mined_block_with_prev_hash_and_transactions(
        genesis.block_hash(),
        vec![coinbase_transaction(1)],
    )?;
    let right = mined_block_with_prev_hash_and_transactions(
        genesis.block_hash(),
        vec![coinbase_transaction(2)],
    )?;
    assert_ne!(
        left.block_hash(),
        right.block_hash(),
        "the two candidates must differ or this races nothing"
    );

    let outcomes = std::thread::scope(|scope| {
        let a = scope.spawn(|| handles.apply_block(&left).map(|outcome| outcome.tip));
        let b = scope.spawn(|| handles.apply_block(&right).map(|outcome| outcome.tip));
        (a.join(), b.join())
    });
    let (Ok(left_outcome), Ok(right_outcome)) = outcomes else {
        panic!("an applier thread panicked");
    };

    let winners = usize::from(left_outcome.is_ok()) + usize::from(right_outcome.is_ok());
    assert_eq!(
        winners, 1,
        "exactly one connect may win the height, got left={left_outcome:?} right={right_outcome:?}"
    );

    let tip = handles
        .applied_tip
        .load_full()
        .ok_or("no applied tip after the race")?;
    assert_eq!(tip.height, 1, "the tip must advance exactly one block");
    let winner = if left_outcome.is_ok() { &left } else { &right };
    assert_eq!(
        tip.hash,
        Hash256::from(winner.block_hash()),
        "the published tip must be the block that actually won"
    );
    Ok(())
}

/// The ordering contract: undo is written before the UTXO commit and before
/// every derived write, so a failure to record it must leave the node
/// exactly as it was. Applying the block anyway would produce a chainstate
/// the node cannot disconnect.
#[test]
#[allow(clippy::arc_with_non_send_sync)]
fn a_failed_undo_write_applies_nothing() -> Result<(), Box<dyn std::error::Error>> {
    let genesis = Network::Regtest.genesis_block();
    let utxo = Arc::new(UtxoSet::new());
    let mut handles = apply_handles_without_tx_index(Network::Regtest, Arc::clone(&utxo));
    handles.undo_store = Arc::new(RejectingUndoStore);
    let genesis_tip =
        applied_header_tip(&handles, Hash256::from(genesis.block_hash()), &genesis, 0)?;
    handles.applied_tip.store(Some(Arc::new(genesis_tip)));

    let block = mined_block_with_prev_hash_and_transactions(
        genesis.block_hash(),
        vec![coinbase_transaction(1)],
    )?;
    let outcome = handles.apply_block(&block).map(|outcome| outcome.tip);

    assert!(
        matches!(outcome, Err(ApplyError::UndoPersistence(_))),
        "a failed undo write must fail the apply, got {outcome:?}"
    );
    assert_eq!(
        utxo.len(),
        0,
        "no UTXO mutation may survive a refused undo write"
    );
    assert_eq!(
        handles
            .applied_tip
            .load()
            .as_ref()
            .map_or(u32::MAX, |tip| tip.height),
        0,
        "the applied tip must not advance"
    );
    Ok(())
}

#[test]
#[allow(clippy::arc_with_non_send_sync)]
fn apply_block_does_not_require_a_transaction_index() -> Result<(), Box<dyn std::error::Error>> {
    let genesis = Network::Regtest.genesis_block();
    let handles = apply_handles_without_tx_index(Network::Regtest, Arc::new(UtxoSet::new()));
    let genesis_tip =
        applied_header_tip(&handles, Hash256::from(genesis.block_hash()), &genesis, 0)?;
    handles.applied_tip.store(Some(Arc::new(genesis_tip)));
    let block = mined_block_with_prev_hash_and_transactions(
        genesis.block_hash(),
        vec![coinbase_transaction(1)],
    )?;

    handles.apply_block(&block)?;
    Ok(())
}
