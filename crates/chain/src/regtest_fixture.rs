//! Regtest fixture builders for cross-crate test harnesses.
//!
//! Every returned block meets its declared compact target, carries a
//! version-4 header (regtest's BIP34 height is 500, and longer fixture chains
//! must clear the shared contextual header gate), has a header merkle root
//! equal to the consensus fold over its transactions, and spends the null
//! outpoint at sequence MAX in its coinbase.

use bitcoin_rs_consensus::{block_subsidy, compute_merkle_root};
use bitcoin_rs_primitives::{
    Amount, Block, BlockHash, CompactTarget, Hash256, Header, LockTime, Network, OutPoint, Script,
    Sequence, Tx, TxIn, TxOut, Witness,
};

use crate::compact_is_met_by;

/// The regtest easy target every fixture grinds (`0x207f_ffff`).
pub const REGTEST_BITS: u32 = 0x207f_ffff;

/// Fixture failure: the nonce space is exhausted, or a block carries no
/// transactions.
#[derive(Debug, thiserror::Error)]
pub enum RegtestFixtureError {
    /// The 32-bit header nonce space was exhausted without meeting the target.
    #[error("test fixture exhausted the header nonce space")]
    NonceExhausted,
    /// The transaction list was empty, so no merkle root exists.
    #[error("test fixture block carries no transactions")]
    EmptyMerkleRoot,
}

/// Regtest genesis header time (matches `Network::Regtest.genesis_block()`).
#[must_use]
pub fn genesis_time() -> u32 {
    Network::Regtest.genesis_block().header.time
}

/// Minimal sign-magnitude `CScriptNum` push.
///
/// Mirrors `bitcoin_rs_script::push_int`, the encoding the BIP34 checker
/// expects, without pulling the script crate into chain.
#[must_use]
pub fn script_num_push(value: i64) -> Vec<u8> {
    if value == 0 {
        return vec![0x00]; // OP_0
    }
    if value == -1 {
        return vec![0x4f]; // OP_1NEGATE
    }
    if (1..=16).contains(&value) {
        let small = u8::try_from(value).unwrap_or_default();
        return vec![0x50 + small]; // OP_1..OP_16
    }
    let negative = value < 0;
    let mut magnitude = value.unsigned_abs();
    let mut bytes = Vec::new();
    while magnitude > 0 {
        bytes.push(u8::try_from(magnitude & 0xff).unwrap_or_default());
        magnitude >>= 8;
    }
    if let Some(last) = bytes.last_mut() {
        if *last & 0x80 != 0 {
            bytes.push(if negative { 0x80 } else { 0x00 });
        } else if negative {
            *last |= 0x80;
        }
    }
    let mut out = Vec::with_capacity(bytes.len() + 1);
    out.push(u8::try_from(bytes.len()).unwrap_or_default());
    out.extend_from_slice(&bytes);
    out
}

/// The canonical one-coinbase transaction for `height`.
///
/// The scriptSig is `script_num_push(height)` plus an `OP_0` extranonce byte,
/// because consensus requires 2..=100 scriptSig bytes and the height push
/// alone is one byte for heights 1..=16. The output pays the regtest subsidy
/// at `height` rather than a fixed amount, so fixtures stay valid past a
/// halving.
#[must_use]
pub fn coinbase(height: u32) -> Tx {
    let mut script_sig = script_num_push(i64::from(height));
    script_sig.extend_from_slice(&script_num_push(0));
    Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: Script::from_bytes(script_sig),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(block_subsidy(
                height,
                Network::Regtest.subsidy_halving_interval(),
            )),
            script_pubkey: Script::new(),
        }],
    }
}

/// Consensus merkle root over transaction ids, `None` only when `txs` is empty.
#[must_use]
pub fn merkle_root(txs: &[Tx]) -> Option<Hash256> {
    let mut leaves: Vec<[u8; 32]> = txs.iter().map(|tx| *tx.txid().as_bytes()).collect();
    compute_merkle_root(&mut leaves).map(|root| Hash256::from_le_bytes(&root))
}

/// Grinds `header.nonce` until the header hash meets `header.bits`.
pub fn mine_header_to_declared_target(header: &mut Header) -> Result<(), RegtestFixtureError> {
    while !compact_is_met_by(header.bits, Hash256::from(header.compute_hash())) {
        header.nonce = header
            .nonce
            .checked_add(1)
            .ok_or(RegtestFixtureError::NonceExhausted)?;
    }
    Ok(())
}

/// Grinds `block.header.nonce` until the block hash meets `header.bits`.
///
/// PRE: `header.bits` is a valid nonzero compact target.
/// POST: the block hash meets the declared target; transactions are untouched.
pub fn mine_block_to_declared_target(block: &mut Block) -> Result<(), RegtestFixtureError> {
    mine_header_to_declared_target(&mut block.header)
}

/// Mines a one-coinbase child of `prev_blockhash` at `height`, header time
/// `genesis_time() + height`.
pub fn mined_regtest_child_at(
    prev_blockhash: BlockHash,
    height: u32,
) -> Result<Block, RegtestFixtureError> {
    mined_regtest_child_at_time(
        prev_blockhash,
        genesis_time().saturating_add(height),
        height,
    )
}

/// Mines a one-coinbase child at an explicit header time (journal and
/// state-machine fixtures that pin times near genesis).
pub fn mined_regtest_child_at_time(
    prev_blockhash: BlockHash,
    time: u32,
    height: u32,
) -> Result<Block, RegtestFixtureError> {
    build_block(prev_blockhash, time, vec![coinbase(height)])
}

/// Mines a block with caller-supplied transactions (p2p multi-tx fixtures).
/// PRE: `txs` is non-empty.
pub fn mined_block_with_prev_hash(
    prev_blockhash: BlockHash,
    height: u32,
    txs: Vec<Tx>,
) -> Result<Block, RegtestFixtureError> {
    build_block(prev_blockhash, genesis_time().saturating_add(height), txs)
}

/// Mines a header-only fixture (merkle root left zero, header `version: 4`),
/// as the p2p header tests build before mutating bits or time.
pub fn mined_regtest_header(
    prev_blockhash: BlockHash,
    height: u32,
) -> Result<Header, RegtestFixtureError> {
    let mut header = Header {
        version: 4,
        prev_blockhash,
        merkle_root: Hash256::default(),
        time: genesis_time().saturating_add(height),
        bits: CompactTarget::from_consensus(REGTEST_BITS),
        nonce: 0,
    };
    mine_header_to_declared_target(&mut header)?;
    Ok(header)
}

/// Shared builder body for the three block fixtures: header `version: 4`,
/// regtest bits, merkle root bound to the transaction list, nonce ground from
/// zero. No boolean selector parameters; variant selection is by named
/// function.
fn build_block(
    prev_blockhash: BlockHash,
    time: u32,
    txs: Vec<Tx>,
) -> Result<Block, RegtestFixtureError> {
    let mut block = Block {
        header: Header {
            version: 4,
            prev_blockhash,
            merkle_root: Hash256::default(),
            time,
            bits: CompactTarget::from_consensus(REGTEST_BITS),
            nonce: 0,
        },
        txs,
    };
    block.header.merkle_root =
        merkle_root(&block.txs).ok_or(RegtestFixtureError::EmptyMerkleRoot)?;
    mine_block_to_declared_target(&mut block)?;
    Ok(block)
}
