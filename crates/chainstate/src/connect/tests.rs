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
    Amount, Block, BlockHash, LockTime, Network, OutPoint, Script, Sequence, Tx, TxIn, TxOut,
    Witness, deserialize,
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
        handles.apply_block(&block, None)?;
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
        .apply_block(&block, None)
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
    handles.apply_block(&block, None)?;
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
    handles.apply_block(&Network::Signet.genesis_block(), None)?;

    let valid = signet_block_1()?;
    let invalid = with_invalid_solution(&valid)?;
    assert_ne!(invalid.block_hash(), valid.block_hash());

    // A proposal skips the solution, as Core does when it is not checking
    // proof of work; a commit refuses it and leaves the chain usable.
    handles.validate_block(&invalid)?;
    let error = handles
        .apply_block(&invalid, None)
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
    handles.apply_block(&valid, None)?;
    Ok(())
}
