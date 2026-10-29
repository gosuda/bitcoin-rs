use std::sync::Arc;

use bitcoin_rs_chain::NodeStatus;
use bitcoin_rs_chain::regtest_fixture::mined_regtest_child_at as mined_child;
use bitcoin_rs_consensus::ConsensusError;
use bitcoin_rs_primitives::{
    Amount, Block, BlockHash, BlockPayload, CompactTarget, Hash256, Header, LockTime, Network,
    OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid, Witness,
};
use bitcoin_rs_utxo::UtxoSet;
use parking_lot::Mutex;

use super::{ApplyError, AssumeValidGate, Chainstate, WindowApplyDisposition, WindowApplyError};
use crate::test_fixtures::{StagedFire, handles, seed_genesis, staging_recorder};

fn empty_child(prev_blockhash: BlockHash, height: u32) -> Result<Block, &'static str> {
    let mut block = Block {
        header: Header {
            version: 1,
            prev_blockhash,
            merkle_root: Hash256::default(),
            time: 1_296_688_602_u32.saturating_add(height),
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        },
        txs: Vec::new(),
    };
    bitcoin_rs_chain::regtest_fixture::mine_header_to_declared_target(&mut block.header)
        .map_err(|_| "test nonce exhausted")?;
    Ok(block)
}

fn coinbase_less_child(
    prev_blockhash: BlockHash,
    script_len: usize,
) -> Result<Block, Box<dyn std::error::Error>> {
    let tx = Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&[0x42; 32])), 0),
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: Script::from_bytes(vec![0x51; script_len]),
        }],
        lock_time: LockTime::ZERO,
    };
    assert_eq!(tx.base_size(), 60 + script_len);
    let txs = vec![tx];
    let merkle_root =
        bitcoin_rs_chain::regtest_fixture::merkle_root(&txs).ok_or("test body has no root")?;
    let mut header = Header {
        version: 1,
        prev_blockhash,
        merkle_root,
        time: 1_296_688_603,
        bits: CompactTarget::from_consensus(0x207f_ffff),
        nonce: 0,
    };
    bitcoin_rs_chain::regtest_fixture::mine_header_to_declared_target(&mut header)
        .map_err(|_| "test nonce exhausted")?;
    Ok(Block { header, txs })
}

fn deliver_coinbase_less_body(
    script_len: usize,
) -> Result<(WindowApplyError, NodeStatus, NodeStatus, Hash256), Box<dyn std::error::Error>> {
    let genesis = Network::Regtest.genesis_block();
    let chainstate: Chainstate = handles(Network::Regtest, Arc::new(UtxoSet::new()));
    seed_genesis(&chainstate).map_err(|error: ApplyError| error.to_string())?;
    let block = coinbase_less_child(genesis.block_hash(), script_len)?;
    let hash = Hash256::from(block.block_hash());
    chainstate
        .block_tree
        .write()
        .insert_header(block.header, NodeStatus::HeaderValid)?;
    let before = {
        let tree = chainstate.block_tree.read();
        tree.lookup(hash)
            .and_then(|id| tree.node(id).ok())
            .map(|node| node.status)
            .ok_or("the header must be in the tree after insert")?
    };

    let payload = BlockPayload::from_local(block);
    let error = chainstate
        .apply_window(&[&payload])
        .err()
        .ok_or("a coinbase-less body must not commit")?;
    let tree = chainstate.block_tree.read();
    let after = tree
        .lookup(hash)
        .and_then(|id| tree.node(id).ok())
        .map(|node| node.status)
        .ok_or("the header must stay in the tree")?;
    let applied = chainstate
        .applied_tip()
        .load_full()
        .map(|tip| tip.hash)
        .ok_or("an applied tip must be published")?;
    Ok((error, before, after, applied))
}

#[test]
fn a_64_byte_transaction_in_a_coinbase_less_body_leaves_its_header_valid()
-> Result<(), Box<dyn std::error::Error>> {
    let (error, before, after, applied) = deliver_coinbase_less_body(4)?;
    assert!(
        matches!(
            error.source,
            ApplyError::Consensus(ConsensusError::SixtyFourByteMutation)
        ),
        "got {:?}",
        error.source
    );
    assert_eq!(error.disposition, WindowApplyDisposition::BodyMutated);
    assert!(
        error.invalidated.is_empty(),
        "a mutated body must not invalidate its header subtree"
    );
    assert_eq!(
        after, before,
        "a mutated body must preserve its header's preexisting status"
    );
    assert_ne!(
        after,
        NodeStatus::Invalid,
        "a mutated body must not prove its header invalid"
    );
    assert_eq!(
        applied,
        Hash256::from(Network::Regtest.genesis_block().block_hash()),
        "a rejected body must not move the applied tip"
    );
    Ok(())
}

#[test]
fn a_coinbase_less_body_of_another_size_still_poisons_its_header()
-> Result<(), Box<dyn std::error::Error>> {
    let (error, _, status, _) = deliver_coinbase_less_body(0)?;
    assert!(
        matches!(
            error.source,
            ApplyError::Consensus(ConsensusError::MissingCoinbase)
        ),
        "got {:?}",
        error.source
    );
    assert_eq!(error.disposition, WindowApplyDisposition::Permanent);
    assert_eq!(error.invalidated.len(), 1);
    assert_eq!(status, NodeStatus::Invalid);
    Ok(())
}

#[test]
fn window_invalidation_reevaluates_assume_valid() -> Result<(), Box<dyn std::error::Error>> {
    let genesis = Network::Regtest.genesis_block();
    let mut handles: Chainstate = handles(Network::Regtest, Arc::new(UtxoSet::new()));
    seed_genesis(&handles).map_err(|error: ApplyError| error.to_string())?;

    let anchor = empty_child(genesis.block_hash(), 1)?;
    let anchor_hash = Hash256::from(anchor.block_hash());
    handles
        .block_tree
        .write()
        .insert_header(anchor.header, NodeStatus::HeaderValid)?;
    handles.assume_valid_gate = Arc::new(AssumeValidGate::with_anchor(Some((1, anchor_hash))));
    handles
        .assume_valid_gate
        .evaluate(&handles.block_tree.read());
    assert!(
        handles.assume_valid_gate.trusted(),
        "the anchor on the active header chain must start trusted"
    );

    let anchor_payload = BlockPayload::from_local(anchor);
    let outcome = handles.apply_window(&[&anchor_payload]);
    let error = outcome.err().ok_or("an empty block must not commit")?;
    assert_eq!(error.disposition, WindowApplyDisposition::Permanent);
    assert_eq!(error.invalidated.to_vec(), vec![anchor_hash]);

    assert!(
        !handles.assume_valid_gate.trusted(),
        "window invalidation must re-evaluate the assume-valid gate"
    );
    let tip = handles
        .chain_tip()
        .load_full()
        .ok_or("window invalidation must republish the best valid tip")?;
    assert_eq!(tip.hash, Hash256::from(genesis.block_hash()));
    Ok(())
}

#[test]
fn a_failing_window_stages_only_its_last_successful_block() -> Result<(), Box<dyn std::error::Error>>
{
    let genesis = Network::Regtest.genesis_block();
    let genesis_hash = Hash256::from(genesis.block_hash());
    let chainstate: Chainstate = handles(Network::Regtest, Arc::new(UtxoSet::new()));
    seed_genesis(&chainstate).map_err(|error: ApplyError| error.to_string())?;
    chainstate.durable_head.commit(
        None,
        &bitcoin_rs_storage::DurableHead {
            assumeutxo: bitcoin_rs_storage::assumeutxo::AssumeUtxoDiskStatus::Uninitialized,
            commit_id: 1,
            height: 0,
            tip: genesis_hash,
            chain_tx_count: 1,
            body_extent: None,
            undo_extent: None,
        },
        &bitcoin_rs_storage::CommitRecords::default(),
    )?;

    let first = mined_child(genesis.block_hash(), 1)?;
    let second = mined_child(first.block_hash(), 2)?;
    let second_hash = Hash256::from(second.block_hash());
    let bad = empty_child(second.block_hash(), 3)?;
    let bad_hash = Hash256::from(bad.block_hash());
    {
        let mut tree = chainstate.block_tree.write();
        bitcoin_rs_chain::accept_headers(
            &mut tree,
            &[first.header, second.header, bad.header],
            Network::Regtest,
            bitcoin_rs_chain::current_unix_seconds(),
            bitcoin_rs_chain::HeaderValidationMode::LiveAdmission,
        )?;
    }
    let first_payload = BlockPayload::from_local(first);
    let second_payload = BlockPayload::from_local(second);
    let bad_payload = BlockPayload::from_local(bad);
    let payloads = [&first_payload, &second_payload, &bad_payload];

    let fires: Arc<Mutex<Vec<StagedFire>>> = Arc::new(Mutex::new(Vec::new()));
    chainstate
        .set_tip_staged(staging_recorder(&chainstate, &fires))
        .map_err(|_| "the staged-tip hook installs once")?;

    let error = chainstate
        .apply_window(&payloads)
        .err()
        .ok_or("an empty trailing body must not commit")?;
    assert!(
        matches!(
            error.source,
            ApplyError::Consensus(ConsensusError::EmptyBlock)
        ),
        "got {:?}",
        error.source
    );
    assert_eq!(error.disposition, WindowApplyDisposition::Permanent);
    assert_eq!(error.applied, 2, "two blocks committed before the failure");
    assert_eq!(error.committed.len(), 2);
    assert_eq!(
        error.committed[1].hash, second_hash,
        "the committed prefix ends at the last successful block"
    );

    let fires = fires.lock();
    assert_eq!(
        fires.len(),
        1,
        "the failure-prefix flush hands off exactly one staged tip"
    );
    assert_eq!(
        fires[0].staged_hash, second_hash,
        "the handoff names the last successful block, not the failed one"
    );
    assert_eq!(fires[0].staged_height, 2);
    assert_eq!(
        fires[0].block_hash, second_hash,
        "the borrowed body is the last success, never the failed block"
    );
    assert!(
        fires[0].block_hash != bad_hash,
        "the failed block must never reach the hook"
    );
    assert_eq!(
        fires[0].published,
        Some((genesis_hash, 0)),
        "the applied tip is still the pre-window tip at fire time"
    );

    let applied = chainstate
        .applied_tip_snapshot()
        .ok_or("the committed prefix must publish an applied tip")?;
    assert_eq!(
        applied.hash, second_hash,
        "the failure-prefix flush publishes the last success, not the failure"
    );
    Ok(())
}
