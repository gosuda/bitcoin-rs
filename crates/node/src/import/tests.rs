use super::*;
use bitcoin_rs_primitives::Block;
use bitcoin_rs_primitives::BlockHash;
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_primitives::Header;
use bitcoin_rs_primitives::OutPoint;
use bitcoin_rs_primitives::Tx;
use bitcoin_rs_primitives::TxIn;
use bitcoin_rs_primitives::TxOut;
use bitcoin_rs_primitives::Txid;
use bitcoin_rs_primitives::consensus_bytes;
use bitcoin_rs_primitives::encode::double_sha256;
use std::time::Duration;
use std::time::Instant;
use tempfile::tempdir;

const REGTEST_GENESIS_HEX: &str = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff7f20020000000101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000";

fn compute_merkle_root(block: &Block) -> Option<Hash256> {
    let mut leaves: Vec<[u8; 32]> = block.txs.iter().map(|tx| *tx.txid().as_bytes()).collect();
    if leaves.is_empty() {
        return None;
    }
    while leaves.len() > 1 {
        let original_len = leaves.len();
        let mut next = Vec::with_capacity(original_len.div_ceil(2));
        for pos in 0..original_len.div_ceil(2) {
            let left = leaves[2 * pos];
            let right = leaves[(2 * pos + 1).min(original_len - 1)];
            let mut pair = [0_u8; 64];
            pair[..32].copy_from_slice(&left);
            pair[32..].copy_from_slice(&right);
            next.push(double_sha256(&pair).to_le_bytes());
        }
        leaves = next;
    }
    Some(Hash256::from_le_bytes(&leaves[0]))
}

fn pow_met(bits: u32, hash: Hash256) -> bool {
    // Interpret the hash as a little-endian 256-bit integer and compare it
    // against the decoded compact target. Regtest bits 0x207f_ffff is the
    // easiest target (about half of all hashes pass); lower targets reject
    // more. Both arrays are reversed into big-endian order so `[u8; 32]`
    // ordering is numeric ordering.
    let target = uint_be(&compact_to_target(bits));
    if target == [0_u8; 32] {
        return false;
    }
    uint_be(&hash.to_le_bytes()) <= target
}

fn compact_to_target(bits: u32) -> [u8; 32] {
    let exponent = usize::from(u8::try_from(bits >> 24).unwrap_or(0));
    let mantissa = u64::from(bits & 0x007f_ffff);
    let mut target = [0_u8; 32];
    if exponent <= 3 {
        let val = mantissa >> (8 * (3 - exponent));
        target[..8].copy_from_slice(&val.to_le_bytes());
    } else {
        let shift = 8 * (exponent - 3);
        if shift < 256 {
            let byte_shift = shift / 8;
            for (offset, &byte) in mantissa.to_le_bytes().iter().enumerate() {
                let position = byte_shift + offset;
                if position < 32 {
                    target[position] = byte;
                }
            }
        }
    }
    if mantissa != 0 && bits & 0x0080_0000 != 0 {
        return [0_u8; 32];
    }
    if mantissa != 0
        && (exponent > 34
            || (mantissa > 0xff && exponent > 33)
            || (mantissa > 0xffff && exponent > 32))
    {
        return [0_u8; 32];
    }
    target
}

/// Reverses a 32-byte little-endian integer so array ordering is numeric.
fn uint_be(bytes: &[u8; 32]) -> [u8; 32] {
    let mut arr = [0_u8; 32];
    arr.copy_from_slice(bytes);
    arr.reverse();
    arr
}

fn mine_header_to_declared_target(header: &mut Header) -> Result<()> {
    while !pow_met(header.bits.to_consensus(), header.compute_hash().0) {
        header.nonce = header
            .nonce
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("exhausted nonce while mining test header"))?;
    }
    Ok(())
}

fn mine_block_to_declared_target(block: &mut Block) -> Result<()> {
    while !pow_met(block.header.bits.to_consensus(), block.block_hash().0) {
        block.header.nonce = block
            .header
            .nonce
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("exhausted nonce while mining test block"))?;
    }
    Ok(())
}

fn encode_block(block: &Block) -> Vec<u8> {
    consensus_bytes(block)
}

fn seed_synthetic_header_tip(
    state: &NodeState,
    height: u32,
) -> Result<bitcoin_rs_chain::TipSnapshot> {
    let block_tree = state.block_tree();
    let mut tree = block_tree.write();
    let bits = 0x207f_ffff;
    let mut parent = None;
    let mut prev_blockhash = BlockHash(Hash256::from_le_bytes(&[0_u8; 32]));
    let mut tip = None;

    for current_height in 0..=height {
        let mut merkle = [0_u8; 32];
        merkle[..4].copy_from_slice(&current_height.to_le_bytes());
        let mut header = Header {
            version: 1,
            prev_blockhash,
            merkle_root: Hash256::from_le_bytes(&merkle),
            time: current_height,
            bits: CompactTarget::from_consensus(bits),
            nonce: 0,
        };
        mine_header_to_declared_target(&mut header)?;
        let node_id =
            tree.insert_node(parent, header, bitcoin_rs_chain::NodeStatus::HeaderValid)?;
        let node = tree.node(node_id)?;
        let snapshot = bitcoin_rs_chain::TipSnapshot {
            tip_id: node_id,
            height: node.height,
            chainwork: node.chainwork,
            hash: node.hash,
        };
        prev_blockhash = header.compute_hash();
        parent = Some(node_id);
        tip = Some(snapshot);
    }

    let tip = tip.ok_or_else(|| anyhow::anyhow!("synthetic header chain should not be empty"))?;
    drop(tree);
    state
        .chain_tip()
        .store(Some(std::sync::Arc::new(tip.clone())));
    state
        .applied_tip()
        .store(Some(std::sync::Arc::new(tip.clone())));
    Ok(tip)
}

fn hex_decode(hex: &str) -> Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    let chars: Vec<char> = hex.chars().collect();
    for pair in chars.chunks(2) {
        let high = pair[0]
            .to_digit(16)
            .with_context(|| format!("non-hex char {}", pair[0]))?;
        let low = pair[1]
            .to_digit(16)
            .with_context(|| format!("non-hex char {}", pair[1]))?;
        bytes.push(u8::try_from((high << 4) | low).with_context(|| "hex value out of u8 range")?);
    }
    Ok(bytes)
}

#[cfg(test)]
mod behavior_1;

#[cfg(test)]
mod notifications_1;

#[cfg(test)]
mod validation_1;
