//! Regtest fixture builders for cross-crate test harnesses.
//!
//! PRE: the caller supplies a parent hash, a height, and (where a non-default
//! timestamp is needed) a header time.
//! POST: every returned block meets its declared compact target, its header
//! carries a version-4 number (regtest rejects version 1 from the BIP34
//! height 500, and longer fixture chains must connect through the shared
//! contextual header gate), its header merkle root equals the consensus fold
//! over its transactions, and its coinbase spends the null outpoint at
//! sequence MAX.
//! INVARIANT: a returned block is accepted by `validate_pow` and its header
//! merkle root equals `merkle_root(&block.txs)`.

use bitcoin_rs_consensus::compute_merkle_root;
use bitcoin_rs_primitives::{
    Amount, Block, BlockHash, CompactTarget, Hash256, Header, LockTime, Network, OutPoint, Script,
    Sequence, Tx, TxIn, TxOut, Txid, Witness,
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

/// Sign-magnitude `CScriptNum` push (the encoding the node and p2p fixtures use).
///
/// Mirrors `bitcoin_rs_script::push_int`, which is also the encoding the
/// BIP34 checker expects, without pulling a script-crate dependency into
/// chain: `OP_0` for zero, `OP_1NEGATE` for minus one, `OP_1`..`OP_16` for
/// 1..=16, and a length-prefixed sign-magnitude push otherwise.
///
/// PRE: `value` is a BIP34-height-sized integer.
/// POST: the returned bytes are a minimal script-num push.
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
/// PRE: `height` fits an i64 script number.
/// POST: the coinbase spends the null outpoint, carries `script_num_push(height)`
/// followed by an `OP_0` extranonce byte in its scriptSig (consensus requires
/// 2..=100 scriptSig bytes, and the height push alone is one byte for heights
/// 1..=16), and pays 1 sat to an empty script.
#[must_use]
pub fn coinbase(height: u32) -> Tx {
    let mut script_sig = script_num_push(i64::from(height));
    script_sig.extend_from_slice(&script_num_push(0));
    Tx {
        version: 2,
        lock_time: LockTime::from_consensus(0),
        inputs: vec![TxIn {
            previous_output: OutPoint::new(Txid::default(), u32::MAX),
            script_sig: Script::from_bytes(script_sig),
            sequence: Sequence::from_consensus(u32::MAX),
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: Script::new(),
        }],
    }
}

/// Consensus merkle root over transaction ids.
///
/// POST: `None` only for an empty transaction list.
#[must_use]
pub fn merkle_root(txs: &[Tx]) -> Option<Hash256> {
    let mut leaves: Vec<[u8; 32]> = txs.iter().map(|tx| *tx.txid().as_bytes()).collect();
    compute_merkle_root(&mut leaves).map(|root| Hash256::from_le_bytes(&root))
}

/// Grinds `header.nonce` until the header hash meets `header.bits`.
///
/// PRE: `header.bits` is a valid nonzero compact target.
/// POST: `compact_is_met_by(header.bits, hash)` holds for the final header.
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
