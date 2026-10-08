//! Fixed BIP141 witness-commitment vector.
//!
//! The candidate assembly output is pinned three ways: against hard-coded
//! commitment bytes derived out-of-band with coreutils `sha256sum`, against
//! `bitcoin::Block::witness_root` (rust-bitcoin's own BIP141 implementation),
//! and against the byte layout of the `OP_RETURN` commitment script.

#[path = "common/fixtures.rs"]
mod common;

use std::error::Error;

use bitcoin::consensus::encode::serialize as bitcoin_serialize;
use bitcoin::hashes::{Hash as _, HashEngine as _, sha256d};
use bitcoin::opcodes::all::{OP_PUSHBYTES_36, OP_RETURN};
use bitcoin::{block, pow};
use bitcoin_rs_mempool::{Mempool, MempoolLimits, MempoolMiningSnapshot};
use bitcoin_rs_mining::{
    CandidateContext, WITNESS_RESERVED_VALUE, assemble_candidate, witness_commitment_script,
};
use bitcoin_rs_primitives::{Amount, Hash256, Tx};
use common::{PAYOUT, insert, oracle_transaction, witnessed_tx};

fn context() -> CandidateContext {
    CandidateContext {
        previous_block_hash: Hash256::from_le_bytes(&[0xab; 32]),
        height: 1,
        min_time: 1_700_000_001,
        current_time: 1_700_000_600,
        locktime_cutoff: 1_700_000_000,
        ..common::context()
    }
}

/// Pinned commitment bytes for the vector below, derived by piping
/// `witness_root || reserved_value` through `sha256sum` twice with coreutils,
const VECTOR_COMMITMENT: [u8; 32] = [
    0xd2, 0x31, 0x9f, 0x64, 0x3d, 0x27, 0xbc, 0x0e, 0xcb, 0xa4, 0xf0, 0xc8, 0xb6, 0x90, 0xef, 0x3e,
    0xb6, 0x4f, 0x69, 0x21, 0x65, 0xec, 0x29, 0x41, 0xf2, 0x3e, 0xac, 0xb0, 0x64, 0x76, 0xec, 0xe6,
];

#[test]
fn witness_commitment_matches_pinned_vector_and_rust_bitcoin_root() -> Result<(), Box<dyn Error>> {
    let parent = witnessed_tx(1, 50_000, None);
    let child = witnessed_tx(2, 40_000, Some(parent.txid()));
    let snapshot = snapshot_with(&[parent.clone(), child.clone()], &[2_000, 3_000])?;

    let candidate = assemble_candidate(&context(), &snapshot, PAYOUT)?;
    let commitment = candidate
        .witness_commitment
        .ok_or("segwit-active candidate must carry a commitment")?;
    let root = candidate
        .witness_merkle_root
        .ok_or("segwit-active candidate must carry a witness root")?;

    // 1. Pinned out-of-band vector.
    assert_eq!(
        commitment.as_byte_array(),
        &VECTOR_COMMITMENT,
        "assembled commitment diverges from the pinned BIP141 vector"
    );

    // 2. rust-bitcoin's witness root over the same tx set (coinbase wtxid
    //    replaced with zeros per BIP141). Both roots are compared as raw
    //    consensus bytes so the digest byte order has exactly one owner.
    let oracle_block = block::Block {
        header: block::Header {
            version: block::Version::from_consensus(0x2000_0000),
            prev_blockhash: block::BlockHash::from_byte_array([0xab; 32]),
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time: 1_700_000_600,
            bits: pow::CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        },
        txdata: vec![
            oracle_transaction(&candidate.coinbase)?,
            oracle_transaction(&parent)?,
            oracle_transaction(&child)?,
        ],
    };
    let oracle_root = oracle_block
        .witness_root()
        .ok_or("oracle block must yield a witness root")?;
    assert_eq!(
        bitcoin_serialize(&oracle_root),
        root.as_byte_array().to_vec(),
        "witness merkle root diverges from the rust-bitcoin oracle"
    );

    // 3. Commitment recomputed from the oracle root over the reserved value.
    let mut engine = sha256d::Hash::engine();
    engine.input(bitcoin_serialize(&oracle_root).as_slice());
    engine.input(&WITNESS_RESERVED_VALUE);
    let recomputed = sha256d::Hash::from_engine(engine);
    assert_eq!(
        bitcoin_serialize(&recomputed),
        commitment.as_byte_array().to_vec(),
        "commitment is not dSHA256(witness_root || reserved_value)"
    );

    // Byte equality of the commitment output script against the pinned bytes.
    let script = witness_commitment_script(&commitment);
    assert_eq!(
        script,
        commitment_script_bytes(&VECTOR_COMMITMENT),
        "commitment output script diverges from the pinned BIP141 script bytes"
    );

    // The coinbase actually carries the commitment output and the reserved value.
    let commitment_output = candidate
        .coinbase
        .outputs
        .iter()
        .find(|output| output.script_pubkey == script)
        .ok_or("coinbase must carry the commitment output script")?;
    assert_eq!(commitment_output.value, Amount::ZERO);
    assert_eq!(
        candidate.coinbase.inputs[0].witness,
        vec![WITNESS_RESERVED_VALUE.to_vec()],
        "coinbase witness must be exactly the 32-byte reserved value"
    );

    // Legacy fallback: no commitment anywhere when segwit is inactive.
    let legacy = assemble_candidate(
        &CandidateContext {
            segwit_active: false,
            ..context()
        },
        &snapshot_with(&[witnessed_tx(1, 50_000, None)], &[2_000])?,
        PAYOUT,
    )?;
    assert!(legacy.witness_commitment.is_none());
    assert!(legacy.witness_merkle_root.is_none());
    assert!(legacy.witness_reserved_value.is_none());
    assert!(
        !legacy
            .coinbase
            .outputs
            .iter()
            .any(|output| output.script_pubkey.first() == Some(&0x6a))
    );
    assert!(legacy.coinbase.inputs[0].witness.is_empty());
    Ok(())
}

fn snapshot_with(txs: &[Tx], fees: &[u64]) -> Result<MempoolMiningSnapshot, Box<dyn Error>> {
    assert_eq!(txs.len(), fees.len());
    let mut pool = Mempool::new(MempoolLimits::default());
    for (tx, &fee) in txs.iter().zip(fees) {
        insert(&mut pool, tx.clone(), u32::try_from(tx.vsize())?, fee, 0, 0)?;
    }
    Ok(pool.mining_snapshot())
}

/// `OP_RETURN OP_PUSHBYTES_36 aa21a9ed <32-byte commitment>`.
fn commitment_script_bytes(commitment: &[u8; 32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(38);
    bytes.push(OP_RETURN.to_u8());
    bytes.push(OP_PUSHBYTES_36.to_u8());
    bytes.extend_from_slice(&[0xaa, 0x21, 0xa9, 0xed]);
    bytes.extend_from_slice(commitment);
    bytes
}
