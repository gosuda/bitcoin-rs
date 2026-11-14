use std::sync::Arc;

use crate::chain::regtest_fixture::{
    coinbase, merkle_root, mine_block_to_declared_target, mined_block_with_prev_hash,
    mined_regtest_child_at as mined_child, mined_regtest_child_at_time,
};
use bitcoin_rs_consensus::primitives::{
    Amount, Block, BlockImage, Hash256, LockTime, Network, OutPoint, Script, Sequence, Tx, TxIn,
    TxOut, Witness,
};
use bitcoin_rs_storage::pruning::{HistoryAccess, RetentionBudget};
use bitcoin_rs_storage::utxo::UtxoSet;
use bitcoin_rs_storage::utxo::contract::{
    BlockChanges, UndoCodecError, UndoLoadError, UtxoAdd, populate_block_changes,
};
use bitcoin_rs_storage::{KvUndoStore, MandatoryRetention, RetentionRegistry, UndoStore};

use super::Chainstate;
use crate::test_fixtures::{TestError, TestResult, handles, seed_genesis};
use crate::{ApplyError, DisconnectError};

const PAY_TO_TRUE: u8 = 0x51;

fn remine(block: &mut Block) -> TestResult {
    block.header.merkle_root = merkle_root(&block.txs).ok_or(TestError::Missing("merkle root"))?;
    mine_block_to_declared_target(block)?;
    Ok(())
}

fn pay_to_true(tx: &mut Tx) {
    for output in &mut tx.outputs {
        output.script_pubkey = Script::from_bytes(vec![PAY_TO_TRUE]);
    }
}

fn spend(funding: OutPoint, value: u64) -> Tx {
    Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: funding,
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey: Script::from_bytes(vec![PAY_TO_TRUE]),
        }],
    }
}

struct Fixture {
    chain: Chainstate,
    blocks: Vec<Block>,
    undo: Arc<KvUndoStore<dyn bitcoin_rs_storage::KvStore>>,
    retention: Arc<RetentionRegistry>,
}

fn chain_to(height: u32) -> TestResult<Fixture> {
    let mut chain = handles(Network::Regtest, Arc::new(UtxoSet::new()));
    let undo = Arc::new(KvUndoStore::new(Arc::clone(chain.commit_authority.store())));
    let retention = Arc::new(RetentionRegistry::new());
    let undo_store: Arc<dyn bitcoin_rs_storage::UndoStore> = undo.clone();
    chain.undo_store = undo_store;
    chain.retention = MandatoryRetention::new(Arc::clone(&retention));
    chain.history = HistoryAccess::new(
        Arc::clone(&retention),
        RetentionBudget::from_blocks(
            bitcoin_rs_consensus::primitives::chain_constants::CORE_REORG_SAFETY_MARGIN,
        ),
    );
    seed_genesis(&chain)?;
    let genesis = Network::Regtest.genesis_block();
    let mut blocks = vec![genesis.clone()];
    let mut parent = genesis.block_hash();
    for current in 1..=height {
        let mut block = mined_child(parent, current)?;
        if current == 1 {
            pay_to_true(&mut block.txs[0]);
            remine(&mut block)?;
        }
        chain.apply_block(&BlockImage::from_local(block.clone()))?;
        parent = block.block_hash();
        blocks.push(block);
    }
    Ok(Fixture {
        chain,
        blocks,
        undo,
        retention,
    })
}

fn coinbase_outpoint(block: &Block) -> OutPoint {
    OutPoint::new(block.txs[0].txid(), 0)
}

fn undo_record(
    undo: &KvUndoStore<dyn bitcoin_rs_storage::KvStore>,
    height: u32,
    block: &Block,
) -> TestResult<Vec<u8>> {
    undo.load_undo(height, Hash256::from(block.block_hash()))?
        .ok_or(TestError::Missing("persisted undo record"))
}

// RCV-08
#[test]
fn coinbase_maturity_refuses_depth_99_and_accepts_depth_100() -> TestResult {
    let refused = chain_to(99)?;
    let funding = coinbase_outpoint(&refused.blocks[1]);
    let spend_tx = spend(funding, 4_999_999_000);
    let block = mined_block_with_prev_hash(
        refused.blocks[99].block_hash(),
        100,
        vec![coinbase(100), spend_tx.clone()],
    )?;
    let outcome = refused.chain.apply_block(&BlockImage::from_local(block));
    assert!(
        matches!(
            outcome,
            Err(ApplyError::Consensus(
                bitcoin_rs_consensus::ConsensusError::Bip {
                    bip: "COINBASE_MATURITY",
                    ..
                }
            ))
        ),
        "depth 99 coinbase spend must be refused, got {outcome:?}"
    );
    assert!(
        refused
            .chain
            .utxo_reader()
            .get(&OutPoint::new(spend_tx.txid(), 0))?
            .is_none(),
        "a refused coinbase spend must not enter the UTXO set"
    );
    assert_eq!(
        refused
            .chain
            .applied_tip_snapshot()
            .ok_or(TestError::Missing("tip"))?
            .height,
        99,
        "a refused coinbase spend must not advance the tip"
    );

    let accepted = chain_to(100)?;
    let funding = coinbase_outpoint(&accepted.blocks[1]);
    let spend_tx = spend(funding, 4_999_999_000);
    let block = mined_block_with_prev_hash(
        accepted.blocks[100].block_hash(),
        101,
        vec![coinbase(101), spend_tx.clone()],
    )?;
    accepted.chain.apply_block(&BlockImage::from_local(block))?;
    assert!(
        accepted
            .chain
            .utxo_reader()
            .get(&OutPoint::new(spend_tx.txid(), 0))?
            .is_some(),
        "depth 100 coinbase spend must enter the UTXO set"
    );
    Ok(())
}

// RCV-08
#[test]
fn disconnect_refuses_undo_whose_removed_outpoint_differs_from_the_block() -> TestResult {
    let fixture = chain_to(2)?;
    let block = &fixture.blocks[2];
    let hash = Hash256::from(block.block_hash());
    let mut record = undo_record(&fixture.undo, 2, block)?;
    assert_eq!(
        u32::from_le_bytes(record[33..37].try_into()?),
        0,
        "a coinbase-only block restores no coins"
    );
    assert_eq!(
        u32::from_le_bytes(record[37..41].try_into()?),
        1,
        "a coinbase-only block retains one created outpoint"
    );
    record[73] ^= 0x01;
    fixture.undo.persist_undo(2, hash, &record)?;

    let before = fixture
        .chain
        .applied_tip_snapshot()
        .ok_or(TestError::Missing("applied tip"))?;
    let outcome = fixture.chain.disconnect_block(block);

    let Err(DisconnectError::Refused(error)) = outcome else {
        panic!("a mismatched undo record must refuse the disconnect, got {outcome:?}");
    };
    assert!(
        matches!(
            *error,
            ApplyError::UndoLoad(UndoLoadError::Unreadable {
                source: UndoCodecError::BlockMismatch { .. },
                ..
            })
        ),
        "the refusal must name the block mismatch, got {error:?}"
    );
    assert_eq!(
        fixture
            .chain
            .applied_tip_snapshot()
            .ok_or(TestError::Missing("applied tip"))?
            .hash,
        before.hash,
        "a refused disconnect must not move the tip"
    );
    assert!(
        fixture
            .chain
            .utxo_reader()
            .get(&coinbase_outpoint(block))?
            .is_some(),
        "a refused disconnect must not drop block coins"
    );
    assert_eq!(
        fixture
            .chain
            .durable_head
            .load()?
            .ok_or(TestError::Missing("durable head"))?
            .tip,
        before.hash,
        "a refused disconnect must not move the durable head"
    );
    Ok(())
}

// RCV-08
#[test]
fn disconnect_refuses_missing_or_truncated_undo_and_keeps_state() -> TestResult {
    for truncated in [false, true] {
        let fixture = chain_to(2)?;
        let block = &fixture.blocks[2];
        let hash = Hash256::from(block.block_hash());
        if truncated {
            let record = undo_record(&fixture.undo, 2, block)?;
            fixture
                .undo
                .persist_undo(2, hash, &record[..record.len() - 1])?;
        } else {
            fixture.undo.remove_archived(2, hash)?;
        }

        let outcome = fixture.chain.disconnect_block(block);
        let Err(DisconnectError::Refused(error)) = outcome else {
            panic!("truncated={truncated}: unavailable undo must refuse, got {outcome:?}");
        };
        let expected = if truncated {
            matches!(
                *error,
                ApplyError::UndoLoad(UndoLoadError::Unreadable { .. })
            )
        } else {
            matches!(*error, ApplyError::UndoLoad(UndoLoadError::Missing { .. }))
        };
        assert!(
            expected,
            "truncated={truncated}: unexpected refusal {error:?}"
        );
        assert_eq!(
            fixture
                .chain
                .applied_tip_snapshot()
                .ok_or(TestError::Missing("applied tip"))?
                .hash,
            hash,
            "truncated={truncated}: a refused disconnect must not move the tip"
        );
        assert!(
            fixture
                .chain
                .utxo_reader()
                .get(&coinbase_outpoint(block))?
                .is_some(),
            "truncated={truncated}: a refused disconnect must not drop block coins"
        );
    }
    Ok(())
}

#[test]
fn a_block_with_a_duplicate_live_txid_is_refused_at_any_height() -> TestResult {
    let fixture = chain_to(2)?;
    let funding = OutPoint::new(Hash256::from_le_bytes(&[0xF1; 32]).into(), 0);
    let mut seed = BlockChanges::default();
    seed.add(UtxoAdd::new(
        funding,
        TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: Script::from_bytes(vec![PAY_TO_TRUE]),
        },
        false,
        0,
    ));
    populate_block_changes(&fixture.chain.coins, &seed)?;
    let spend_tx = spend(funding, 900);
    let mut live = BlockChanges::default();
    live.add(UtxoAdd::new(
        OutPoint::new(spend_tx.txid(), 0),
        TxOut {
            value: Amount::from_sat(1),
            script_pubkey: Script::from_bytes(vec![PAY_TO_TRUE]),
        },
        false,
        0,
    ));
    populate_block_changes(&fixture.chain.coins, &live)?;

    let block = mined_block_with_prev_hash(
        fixture.blocks[2].block_hash(),
        3,
        vec![coinbase(3), spend_tx],
    )?;
    let outcome = fixture.chain.apply_block(&BlockImage::from_local(block));
    assert!(
        matches!(
            outcome,
            Err(ApplyError::Consensus(
                bitcoin_rs_consensus::ConsensusError::Bip { bip: "BIP30", .. }
            ))
        ),
        "a duplicate txid with live outputs must be refused, got {outcome:?}"
    );
    Ok(())
}

struct NoopObserver;

impl crate::reorg::ReorgObserver for NoopObserver {
    fn disconnected(&mut self, _: &crate::DisconnectOutcome) {}

    fn connected(
        &mut self,
        _: &bitcoin_rs_consensus::primitives::BlockImage,
        _: &crate::ConnectOutcome,
    ) {
    }

    fn reconsider_disconnected(&mut self, _: &bitcoin_rs_consensus::primitives::BlockImage) {}
}

// RCV-08
#[test]
fn a_reorg_below_the_retained_undo_window_refuses_before_mutation() -> TestResult {
    let fixture = chain_to(6)?;
    let genesis_time = Network::Regtest.genesis_block().header.time;
    let mut parent = fixture.blocks[2].block_hash();
    let mut fork = Vec::new();
    for height in 3..=7 {
        let block = mined_regtest_child_at_time(parent, genesis_time + 100 + height, height)?;
        parent = block.block_hash();
        fork.push(block);
    }
    let headers: Vec<_> = fork.iter().map(|block| block.header).collect();
    fixture.chain.admit_headers(&headers)?;
    let target = fixture
        .chain
        .block_tree
        .read()
        .lookup(Hash256::from(
            fork.last()
                .ok_or(TestError::Missing("fork tip"))?
                .block_hash(),
        ))
        .ok_or(TestError::Missing("fork target in the block tree"))?;

    fixture.retention.reserve(4).commit(4);
    let before = fixture
        .chain
        .applied_tip_snapshot()
        .ok_or(TestError::Missing("applied tip"))?;
    let before_utxo = fixture.chain.utxo.lock_stable_view().hash_serialized_3()?;
    let error = crate::reorg::switch_to_branch(
        &fixture.chain,
        target,
        |_| None,
        &mut NoopObserver,
        |_, outcome| outcome,
    )
    .err()
    .ok_or(TestError::UnexpectedSuccess("a pruned reorg floor"))?;

    assert!(
        matches!(
            error,
            crate::reorg::ReorgError::RetentionUnavailable { floor: 3, .. }
        ),
        "the reorg must refuse at the pruned floor, got {error:?}"
    );
    assert_eq!(
        fixture
            .chain
            .applied_tip_snapshot()
            .ok_or(TestError::Missing("applied tip"))?
            .hash,
        before.hash,
        "a refused reorg must not move the tip"
    );
    assert_eq!(
        fixture.chain.utxo.lock_stable_view().hash_serialized_3()?,
        before_utxo,
        "a refused reorg must not mutate the UTXO set"
    );
    assert_eq!(
        fixture
            .chain
            .durable_head
            .load()?
            .ok_or(TestError::Missing("durable head"))?
            .tip,
        before.hash,
        "a refused reorg must not move the durable head"
    );
    Ok(())
}

#[test]
fn block_output_sums_at_the_money_boundary() -> TestResult {
    let fixture = chain_to(2)?;
    let funding = coinbase_outpoint(&fixture.blocks[1]);
    let max_money = Amount::MAX_MONEY.to_sat();

    let above = mined_block_with_prev_hash(
        fixture.blocks[2].block_hash(),
        3,
        vec![coinbase(3), spend(funding, max_money + 1)],
    )?;
    let outcome = fixture.chain.apply_block(&BlockImage::from_local(above));
    assert!(
        matches!(
            outcome,
            Err(ApplyError::Consensus(
                bitcoin_rs_consensus::ConsensusError::OutputValueOverflow
            ))
        ),
        "a MAX_MONEY+1 output sum must overflow, got {outcome:?}"
    );

    let exact = mined_block_with_prev_hash(
        fixture.blocks[2].block_hash(),
        3,
        vec![coinbase(3), spend(funding, max_money)],
    )?;
    let outcome = fixture.chain.apply_block(&BlockImage::from_local(exact));
    assert!(
        matches!(
            outcome,
            Err(ApplyError::Consensus(
                bitcoin_rs_consensus::ConsensusError::InputsLessThanOutputs { .. }
            ))
        ),
        "a MAX_MONEY output sum must pass the range check, got {outcome:?}"
    );
    Ok(())
}

fn seed_payable_coin(fixture: &Fixture, marker: u8, value: u64) -> TestResult<OutPoint> {
    let outpoint = OutPoint::new(Hash256::from_le_bytes(&[marker; 32]).into(), 0);
    let mut seed = BlockChanges::default();
    seed.add(UtxoAdd::new(
        outpoint,
        TxOut {
            value: Amount::from_sat(value),
            script_pubkey: Script::from_bytes(vec![PAY_TO_TRUE]),
        },
        false,
        0,
    ));
    populate_block_changes(&fixture.chain.coins, &seed)?;
    Ok(outpoint)
}

#[test]
fn a_block_may_spend_a_same_block_output_only_in_creation_order() -> TestResult {
    let forward_fixture = chain_to(2)?;
    let funding = seed_payable_coin(&forward_fixture, 0xF2, 1_000)?;
    let parent = spend(funding, 900);
    let child = spend(OutPoint::new(parent.txid(), 0), 800);
    let forward = mined_block_with_prev_hash(
        forward_fixture.blocks[2].block_hash(),
        3,
        vec![coinbase(3), child.clone(), parent.clone()],
    )?;
    let outcome = forward_fixture
        .chain
        .apply_block(&BlockImage::from_local(forward));
    assert!(
        matches!(
            outcome,
            Err(ApplyError::Consensus(
                bitcoin_rs_consensus::ConsensusError::MissingPrevout { input_index: 0 }
            ))
        ),
        "a forward same-block spend must be refused, got {outcome:?}"
    );
    assert!(
        forward_fixture.chain.utxo_reader().get(&funding)?.is_some(),
        "a refused forward spend must leave the funding coin"
    );
    assert!(
        forward_fixture
            .chain
            .utxo_reader()
            .get(&OutPoint::new(child.txid(), 0))?
            .is_none(),
        "a refused forward spend must not create its output"
    );

    let ordered_fixture = chain_to(2)?;
    let funding = seed_payable_coin(&ordered_fixture, 0xF2, 1_000)?;
    let parent = spend(funding, 900);
    let child = spend(OutPoint::new(parent.txid(), 0), 800);
    let ordered = mined_block_with_prev_hash(
        ordered_fixture.blocks[2].block_hash(),
        3,
        vec![coinbase(3), parent.clone(), child.clone()],
    )?;
    ordered_fixture
        .chain
        .apply_block(&BlockImage::from_local(ordered))?;
    assert!(
        ordered_fixture
            .chain
            .utxo_reader()
            .get(&OutPoint::new(child.txid(), 0))?
            .is_some(),
        "an in-order same-block spend must create its output"
    );
    assert!(
        ordered_fixture
            .chain
            .utxo_reader()
            .get(&OutPoint::new(parent.txid(), 0))?
            .is_none(),
    );
    Ok(())
}

#[test]
fn a_block_cannot_spend_one_coin_twice() -> TestResult {
    let fixture = chain_to(2)?;
    let funding = seed_payable_coin(&fixture, 0xF3, 1_000)?;
    let first = spend(funding, 600);
    let second = spend(funding, 300);
    let block = mined_block_with_prev_hash(
        fixture.blocks[2].block_hash(),
        3,
        vec![coinbase(3), first.clone(), second.clone()],
    )?;
    let outcome = fixture.chain.apply_block(&BlockImage::from_local(block));
    assert!(
        matches!(
            outcome,
            Err(ApplyError::Consensus(
                bitcoin_rs_consensus::ConsensusError::MissingPrevout { input_index: 0 }
            ))
        ),
        "a repeated same-block spend must be refused, got {outcome:?}"
    );
    assert!(
        fixture.chain.utxo_reader().get(&funding)?.is_some(),
        "a refused double spend must leave the funding coin"
    );
    for tx in [&first, &second] {
        assert!(
            fixture
                .chain
                .utxo_reader()
                .get(&OutPoint::new(tx.txid(), 0))?
                .is_none(),
            "a refused double spend must not create outputs"
        );
    }
    Ok(())
}
