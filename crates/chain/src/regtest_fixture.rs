use bitcoin_rs_consensus::{block_subsidy, compute_merkle_root};
use bitcoin_rs_primitives::{
    Amount, Block, BlockHash, CompactTarget, Hash256, Header, LockTime, Network, OutPoint, Script,
    Sequence, Tx, TxIn, TxOut, Witness,
};

use crate::compact_is_met_by;

pub const REGTEST_BITS: u32 = 0x207f_ffff;

#[derive(Debug, thiserror::Error)]
pub enum RegtestFixtureError {
    #[error("test fixture exhausted the header nonce space")]
    NonceExhausted,
    #[error("test fixture block carries no transactions")]
    EmptyMerkleRoot,
}

#[must_use]
pub fn genesis_time() -> u32 {
    Network::Regtest.genesis_block().header.time
}

#[must_use]
pub fn script_num_push(value: i64) -> Vec<u8> {
    if value == 0 {
        return vec![0x00];
    }
    if value == -1 {
        return vec![0x4f];
    }
    if (1..=16).contains(&value) {
        let small = u8::try_from(value).unwrap_or_default();
        return vec![0x50 + small];
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

#[must_use]
pub fn merkle_root(txs: &[Tx]) -> Option<Hash256> {
    let mut leaves: Vec<[u8; 32]> = txs.iter().map(|tx| *tx.txid().as_bytes()).collect();
    compute_merkle_root(&mut leaves).map(|root| Hash256::from_le_bytes(&root))
}

pub fn mine_header_to_declared_target(header: &mut Header) -> Result<(), RegtestFixtureError> {
    while !compact_is_met_by(header.bits, Hash256::from(header.compute_hash())) {
        header.nonce = header
            .nonce
            .checked_add(1)
            .ok_or(RegtestFixtureError::NonceExhausted)?;
    }
    Ok(())
}

pub fn mine_block_to_declared_target(block: &mut Block) -> Result<(), RegtestFixtureError> {
    mine_header_to_declared_target(&mut block.header)
}

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

pub fn mined_regtest_child_at_time(
    prev_blockhash: BlockHash,
    time: u32,
    height: u32,
) -> Result<Block, RegtestFixtureError> {
    build_block(prev_blockhash, time, vec![coinbase(height)])
}

pub fn mined_block_with_prev_hash(
    prev_blockhash: BlockHash,
    height: u32,
    txs: Vec<Tx>,
) -> Result<Block, RegtestFixtureError> {
    build_block(prev_blockhash, genesis_time().saturating_add(height), txs)
}

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
