//! Owner-local connect behavior.
//!
//! BIP68 relative-lock enforcement compares the transaction version as the
//! unsigned wire value (Core's `uint32_t` `CTransaction::version`). BIP325
//! signet solutions are checked when a block commits and not when it is
//! proposed.

use std::sync::Arc;

use bitcoin_rs_chain::regtest_fixture::{
    coinbase, mine_block_to_declared_target, mined_block_with_prev_hash,
    mined_regtest_child_at as mined_child,
};
use bitcoin_rs_consensus::ConsensusError;
use bitcoin_rs_primitives::{
    Amount, Block, BlockHash, BlockPayload, LockTime, Network, OutPoint, Script, Sequence, Tx,
    TxIn, TxOut, Witness, deserialize,
};

use super::ApplyError;
use crate::test_fixtures::{handles, seed_genesis};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn empty_handles() -> Arc<crate::Chainstate> {
    Arc::new(handles(
        Network::Regtest,
        Arc::new(bitcoin_rs_utxo::UtxoSet::new()),
    ))
}

/// Applies `height` mined children on the seeded genesis tip, as the
/// persistence fixtures do: `seed_genesis` publishes the genesis, so only
/// children go through `apply_block`. Returns the final tip block hash.
fn apply_regtest_chain_to_height(
    handles: &crate::Chainstate,
    height: u32,
) -> Result<BlockHash, Box<dyn std::error::Error>> {
    let genesis = Network::Regtest.genesis_block();
    let mut parent = genesis.block_hash();
    for current in 1..=height {
        let block = mined_child(parent, current)?;
        handles.apply_block(&BlockPayload::from_local(block.clone()))?;
        parent = block.block_hash();
    }
    Ok(parent)
}

/// The mature height-1 coinbase spent with `sequence`; the push-only
/// `scriptSig` `[0x51]` keeps the input canonical and the single output
/// satisfies the non-empty-outputs rule.
fn version_max_spend(sequence: u32, version: u32) -> Tx {
    Tx {
        version,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(coinbase(1).txid(), 0),
            script_sig: Script::from_bytes(vec![0x51]),
            sequence: Sequence::from_consensus(sequence),
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: Script::from_bytes(vec![0x51]),
        }],
        lock_time: LockTime::ZERO,
    }
}

/// One `OP_TRUE` spend with the push-only `scriptSig` the mature-coinbase
/// fixture accepts.
fn op_true_spend(previous_output: OutPoint, value: u64) -> Tx {
    Tx {
        version: 1,
        inputs: vec![TxIn {
            previous_output,
            script_sig: Script::from_bytes(vec![0x51]),
            sequence: Sequence::from_consensus(0xffff_ffff),
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey: Script::from_bytes(vec![0x51]),
        }],
        lock_time: LockTime::ZERO,
    }
}

/// `capture_rawtx` only controls whether the commit tail serializes
/// per-transaction wire bytes into the outcome. The connected state
/// (UTXO membership, txids, tip, undo-driven disconnect) must be
/// identical either way, for an external spend and a same-block spend.
#[test]
fn capture_rawtx_changes_only_the_outcome_payload() -> TestResult {
    let external = op_true_spend(OutPoint::new(coinbase(1).txid(), 0), 1_000);
    let same_block = op_true_spend(OutPoint::new(external.txid(), 0), 900);
    let final_outpoint = OutPoint::new(same_block.txid(), 0);
    let intermediate_outpoint = OutPoint::new(external.txid(), 0);
    let spent_outpoint = OutPoint::new(coinbase(1).txid(), 0);

    let mut outcomes = Vec::new();
    let mut undo_records = Vec::new();
    for capture_rawtx in [false, true] {
        let mut handles = handles(Network::Regtest, Arc::new(bitcoin_rs_utxo::UtxoSet::new()));
        seed_genesis(&handles)?;
        let tip_hash = apply_regtest_chain_to_height(&handles, 500)?;
        handles.set_capture_flags(capture_rawtx, false);
        let block = mined_block_with_prev_hash(
            tip_hash,
            501,
            vec![coinbase(501), external.clone(), same_block.clone()],
        )?;
        let outcome = handles.apply_block(&BlockPayload::from_local(block.clone()))?;

        let utxo = handles.utxo();
        assert!(
            utxo.get_entry(&spent_outpoint).is_none(),
            "external coin spent"
        );
        assert!(
            utxo.get_entry(&intermediate_outpoint).is_none(),
            "same-block coin spent"
        );
        let final_coin = utxo
            .get_entry(&final_outpoint)
            .ok_or("final same-block output must be live")?;
        assert_eq!(final_coin.txout.value.to_sat(), 900);

        match (&outcome.raw_txs, capture_rawtx) {
            (None, false) => {}
            (Some(raw_txs), true) => {
                assert_eq!(raw_txs.len(), block.txs.len());
                for (raw, tx) in raw_txs.iter().zip(&block.txs) {
                    assert_eq!(*raw, bitcoin_rs_primitives::consensus_bytes(tx));
                }
            }
            (raw, flag) => panic!("raw_txs presence must follow capture_rawtx={flag}: {raw:?}"),
        }

        // The persisted undo record is part of the durable state and must
        // not depend on the capture flag either.
        let undo = handles
            .undo_store
            .load_undo(501, outcome.hash)?
            .ok_or("a committed block must persist its undo record")?;
        assert!(!undo.is_empty(), "undo record must carry the spent coins");
        undo_records.push(undo);

        // The undo path must restore the pre-block membership identically.
        handles.disconnect_block(&block)?;
        let utxo = handles.utxo();
        assert!(
            utxo.get_entry(&spent_outpoint).is_some(),
            "undo restores coin"
        );
        assert!(
            utxo.get_entry(&final_outpoint).is_none(),
            "undo removes output"
        );
        outcomes.push(outcome);
    }

    let (without, with) = (&outcomes[0], &outcomes[1]);
    assert_eq!(without.txids, with.txids);
    assert_eq!(without.hash, with.hash);
    assert_eq!(without.tip.height, with.tip.height);
    assert_eq!(without.tip.hash, with.tip.hash);
    assert_eq!(without.tip.chain_tx_count, with.tip.chain_tx_count);
    assert_eq!(without.commit_id, with.commit_id);
    assert_eq!(
        undo_records[0], undo_records[1],
        "undo bytes must be identical"
    );
    Ok(())
}

#[test]
fn version_max_tx_enforces_bip68_relative_lock() -> TestResult {
    let handles = empty_handles();
    seed_genesis(&handles)?;

    // The height-1 coinbase is mature at 501; the sequence asks for 1000
    // relative blocks. Version 0xFFFF_FFFF is the unsigned wire value, so the
    // lock applies (Core rejects this spend with `bad-txns-nonfinal`).
    let spend = version_max_spend(1000, u32::MAX);
    let tip_hash = apply_regtest_chain_to_height(&handles, 500)?;
    let mut block = mined_block_with_prev_hash(tip_hash, 501, vec![coinbase(501), spend])?;
    let error = handles
        .apply_block(&BlockPayload::from_local(block.clone()))
        .err()
        .ok_or("an unmet relative lock must reject the block")?;
    let ApplyError::Consensus(bitcoin_rs_consensus::ConsensusError::Bip { bip, .. }) = error else {
        panic!("expected a BIP68 consensus error, got {error:?}");
    };
    assert_eq!(bip, "BIP68");

    // The identical spend at version 1 carries no relative-lock semantics and
    // connects.
    let handles = empty_handles();
    seed_genesis(&handles)?;
    let tip_hash = apply_regtest_chain_to_height(&handles, 500)?;
    block = mined_block_with_prev_hash(
        tip_hash,
        501,
        vec![coinbase(501), version_max_spend(1000, 1)],
    )?;
    handles.apply_block(&BlockPayload::from_local(block))?;
    Ok(())
}

/// The first signet block of Bitcoin Core `test/functional/feature_signet.py`,
/// solved with the default challenge. The consensus crate's signet suite holds
/// all ten blocks; this suite needs one real solved block on top of the signet
/// genesis.
const CORE_SIGNET_BLOCK_1: &str = "00000020f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c4225e973988108000000f575c83235984e7dc4afc1f30944c170462e84437ab6f2d52e16878a79e4678bd1914d5fae77031eccf4070001010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025151feffffff0200f2052a010000001600149243f727dd5343293eb83174324019ec16c2630f0000000000000000776a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf94c4fecc7daa2490047304402205e423a8754336ca99dbe16509b877ef1bf98d008836c725005b3c787c41ebe46022047246e4467ad7cc7f1ad98662afcaf14c115e0095a227c7b05c5182591c23e7e01000120000000000000000000000000000000000000000000000000000000000000000000000000";

/// The marker of the BIP325 solution inside the witness-commitment output.
const SIGNET_HEADER: [u8; 4] = [0xec, 0xc7, 0xda, 0xa2];

fn signet_block_1() -> Result<Block, Box<dyn std::error::Error>> {
    let bytes = (0..CORE_SIGNET_BLOCK_1.len())
        .step_by(2)
        .map(|start| u8::from_str_radix(&CORE_SIGNET_BLOCK_1[start..start + 2], 16))
        .collect::<Result<Vec<u8>, _>>()?;
    Ok(deserialize::<Block>(&bytes)?)
}

/// Offset of the solution header inside `script`, if it carries one.
fn solution_offset(script: &[u8]) -> Option<usize> {
    script
        .windows(SIGNET_HEADER.len())
        .position(|window| window == SIGNET_HEADER.as_slice())
}

/// `valid` with one signature byte flipped, its coinbase id propagated to the
/// header Merkle root, and its proof of work reground: every rule except the
/// signet solution still holds.
fn with_invalid_solution(valid: &Block) -> Result<Block, Box<dyn std::error::Error>> {
    let mut block = valid.clone();
    let (index, solution_at) = block.txs[0]
        .outputs
        .iter()
        .enumerate()
        .find_map(|(index, output)| solution_offset(&output.script_pubkey).map(|at| (index, at)))
        .ok_or("block 1 carries the solution header")?;
    let mut script = block.txs[0].outputs[index].script_pubkey.to_vec();
    script[solution_at + SIGNET_HEADER.len() + 16] ^= 0x01;
    block.txs[0].outputs[index].script_pubkey = Script::from_bytes(script);
    block.header.merkle_root = block.txs[0].txid().into();
    mine_block_to_declared_target(&mut block)?;
    Ok(block)
}

#[test]
fn signet_solution_is_checked_on_commit_not_proposal() -> TestResult {
    let handles = Arc::new(handles(
        Network::Signet,
        Arc::new(bitcoin_rs_utxo::UtxoSet::new()),
    ));
    // The genesis carries no commitment; only its hash exempts it.
    handles.apply_block(&BlockPayload::from_local(Network::Signet.genesis_block()))?;

    let valid = signet_block_1()?;
    let invalid = with_invalid_solution(&valid)?;
    assert_ne!(invalid.block_hash(), valid.block_hash());

    // A proposal skips the solution, as Core does when it is not checking
    // proof of work; a commit refuses it and leaves the chain usable.
    handles.validate_block(&invalid)?;
    let error = handles
        .apply_block(&BlockPayload::from_local(invalid))
        .err()
        .ok_or("a bad solution must not commit")?;
    assert!(
        matches!(error, ApplyError::Consensus(ConsensusError::SignetSolution)),
        "expected a signet solution failure, got {error:?}"
    );
    assert_eq!(
        crate::classify_apply_error(&error),
        crate::WindowApplyDisposition::Permanent,
        "a bad solution invalidates the header branch; it is not retryable"
    );

    handles.validate_block(&valid)?;
    handles.apply_block(&BlockPayload::from_local(valid))?;
    Ok(())
}

use super::*;
use crate::test_fixtures::MemoryBodies;
use bitcoin_rs_chain::regtest_fixture;
use bitcoin_rs_primitives::encode::double_sha256;
use bitcoin_rs_storage::block_body::BlockBodyStore;
use bitcoin_rs_utxo::UtxoSet;

fn witness_child(
    parent: bitcoin_rs_primitives::BlockHash,
    height: u32,
) -> Result<Block, regtest_fixture::RegtestFixtureError> {
    let mut coinbase = regtest_fixture::coinbase(height);
    coinbase.inputs[0].witness = Witness::from_stack(vec![vec![0; 32]]);
    let commitment = double_sha256(&[0; 64]);
    coinbase.outputs.push(TxOut {
        value: Amount::ZERO,
        script_pubkey: [
            vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed],
            commitment.as_byte_array().to_vec(),
        ]
        .concat()
        .into(),
    });
    regtest_fixture::mined_block_with_prev_hash(parent, height, vec![coinbase])
}

#[test]
fn preserved_witness_body_is_bound_before_commit_and_disconnect_keeps_exact_bytes()
-> Result<(), Box<dyn std::error::Error>> {
    for engine in bitcoin_rs_consensus::ValidationEngine::ALL
        .iter()
        .copied()
        .filter(|e| e.is_supported())
    {
        let mut chain = handles(Network::Regtest, Arc::new(UtxoSet::new()));
        chain.validation_engine = engine;
        let bodies = Arc::new(MemoryBodies::default());
        chain.block_body_store = Some(bodies.clone());
        chain.set_capture_flags(false, true);
        let genesis = Network::Regtest.genesis_block();
        chain.apply_block(&BlockPayload::from_local(genesis.clone()))?;
        let child = witness_child(genesis.block_hash(), 1)?;
        let raw = bytes::Bytes::from(consensus_bytes(&child));
        let before = chain.chain_snapshot();
        // Exactness is proved by construction: the split pair is
        // unrepresentable. The stored bytes decode to exactly the valid
        // block, with the preserved hash/body mapping intact.
        let valid = BlockPayload::from_raw(raw.clone()).map_err(|error| error.to_string())?;
        assert_eq!(valid.block().block_hash(), child.block_hash());
        assert_eq!(valid.bytes(), &raw);
        // A witness mutation leaves both txid and serialized length unchanged.
        // It is a different exact payload the valid body's bytes never certify.
        let mut changed = child.clone();
        changed.txs[0].inputs[0].witness = Witness::from_stack(vec![vec![1; 32]]);
        assert_eq!(changed.txs[0].txid(), child.txs[0].txid());
        let changed_payload = BlockPayload::from_local(changed);
        assert_eq!(changed_payload.bytes().len(), raw.len());
        assert_ne!(changed_payload.bytes(), &raw);
        // Truncated bytes are rejected at construction, before apply runs.
        let mut truncated = raw.to_vec();
        truncated.pop();
        assert!(BlockPayload::from_raw(bytes::Bytes::from(truncated)).is_err());
        assert!(matches!(
            chain.apply_block(&changed_payload),
            Err(ApplyError::Consensus(_))
        ));
        assert_eq!(chain.chain_snapshot().tip_hash, before.tip_hash);
        assert!(bodies.load_block_body(1, child.block_hash().0)?.is_none());

        let outcome = chain.apply_block(&valid)?;
        assert_eq!(outcome.block_bytes, raw);
        assert_eq!(
            bodies.load_block_body(1, child.block_hash().0)?.as_deref(),
            Some(raw.as_ref())
        );

        let mut bad_merkle = witness_child(child.block_hash(), 2)?;
        bad_merkle.txs[0].outputs[0].value = Amount::from_sat(1);
        let bad_payload = BlockPayload::from_raw(bytes::Bytes::from(consensus_bytes(&bad_merkle)))
            .map_err(|error| error.to_string())?;
        assert!(chain.apply_block(&bad_payload).is_err());
        assert_eq!(
            chain.applied_tip_snapshot().ok_or("missing tip")?.hash,
            child.block_hash().0
        );
        assert!(
            bodies
                .load_block_body(2, bad_merkle.block_hash().0)?
                .is_none()
        );

        chain.disconnect_block(&child)?;
        let replayed = chain.apply_block(&BlockPayload::from_local(child.clone()))?;
        assert_eq!(replayed.block_bytes, raw);
        assert_eq!(
            bodies.load_block_body(1, child.block_hash().0)?.as_deref(),
            Some(raw.as_ref())
        );
    }
    Ok(())
}
