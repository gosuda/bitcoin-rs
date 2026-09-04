//! Deterministic regtest seed chain, mined through ordinary validation.
//!
//! The blocks are built natively with trivial regtest proof of work (grinding
//! the nonce against the minimum target), each coinbase paying the
//! anyone-can-spend `OP_TRUE` output, and applied through the real
//! `NodeState::apply_block` path. Nothing here fakes mining evidence: the
//! chain exists so the replay has a real, reproducible tip to bind
//! chain-bound keys to.

use super::{GateResult, fail};
use bitcoin_rs_node::{Network, NodeConfig, state::NodeState};
use bitcoin_rs_primitives::encode::double_sha256;
use bitcoin_rs_primitives::{Block, Hash256, OutPoint, Tx, TxIn, TxOut, Txid};

/// Block the seed chain starts from; one minute after the genesis stamp, so
/// mediantime arithmetic matches Core's regtest spacing.
pub(crate) const SEED_BASE_TIME: u32 = 1_296_688_603;
/// Seconds between seed blocks; Core's regtest spacing.
pub(crate) const SEED_BLOCK_INTERVAL: u32 = 600;
/// The never-retargeting regtest minimum target.
pub(crate) const REGTEST_BITS: u32 = 0x207f_ffff;
/// Immature coinbase subsidy on regtest.
pub(crate) const REGTEST_SUBSIDY_SATS: u64 = 50 * 100_000_000;

/// Applies the regtest genesis block; the seed chain builds on it.
///
/// # Errors
/// Propagates validation failures.
pub(crate) fn apply_genesis(state: &NodeState) -> GateResult<()> {
    let genesis = Network::Regtest.genesis_block();
    state.apply_block(&genesis).map_err(fail)?;
    Ok(())
}

/// Chain identity of the mined seed chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SeedChain {
    /// Height of the chain tip.
    pub tip_height: u32,
    /// Tip hash in consensus byte order.
    pub tip_hash: Hash256,
}

/// Mines `count` trivial-PoW regtest blocks through ordinary validation.
///
/// # Errors
/// Propagates validation failures or nonce exhaustion (unreachable at the
/// regtest target).
pub(crate) fn seed_chain(state: &NodeState, count: u32) -> GateResult<SeedChain> {
    let mut tip = current_tip(state)?;
    for height in 1..=count {
        let coinbase = Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: null_prevout(),
                // BIP34 height push plus one pad byte: consensus requires a
                // 2..=100 byte coinbase scriptSig (Core bad-cb-length).
                script_sig: [script_push_int(i64::from(height)), script_push_int(0)].concat(),
                sequence: 0xffff_ffff,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut {
                value: REGTEST_SUBSIDY_SATS,
                script_pubkey: vec![0x51],
            }],
            lock_time: 0,
        };
        let mut block = Block {
            header: bitcoin_rs_primitives::Header {
                version: 0x2000_0000,
                prev_blockhash: bitcoin_rs_primitives::BlockHash::from(tip.hash),
                merkle_root: Hash256::from_le_bytes(&[0_u8; 32]),
                time: SEED_BASE_TIME.saturating_add(SEED_BLOCK_INTERVAL.saturating_mul(height)),
                bits: REGTEST_BITS,
                nonce: 0,
            },
            txs: vec![coinbase],
        };
        block.header.merkle_root = compute_merkle_root(&block.txs)
            .ok_or_else(|| fail("seed block must have a merkle root"))?;
        grind_pow(&mut block)?;
        state.apply_block(&block).map_err(fail)?;
        tip = current_tip(state)?;
        if tip.height != height {
            return Err(fail(format!(
                "seed block must become the tip at height {height}"
            )));
        }
    }
    Ok(SeedChain {
        tip_height: tip.height,
        tip_hash: tip.hash,
    })
}

/// Reads the applied tip; the seed chain is fully applied after each block.
///
/// # Errors
/// Fails when no tip has been published yet.
pub(crate) fn current_tip(state: &NodeState) -> GateResult<bitcoin_rs_chain::TipSnapshot> {
    let applied = state.applied_tip();
    let Some(tip) = applied.load_full() else {
        return Err(fail("applied tip must exist"));
    };
    Ok((*tip).clone())
}

/// Regtest configuration bound to `dir` with no P2P listener.
#[must_use]
pub(crate) fn regtest_config(dir: &std::path::Path) -> NodeConfig {
    let mut config = NodeConfig::default_for_network(Network::Regtest);
    config.data_dir = dir.to_path_buf();
    config.p2p.listen.clear();
    config
}

fn grind_pow(block: &mut Block) -> GateResult<()> {
    loop {
        if pow_is_met(block.header.bits, &block.header.compute_hash().into()) {
            return Ok(());
        }
        let Some(next) = block.header.nonce.checked_add(1) else {
            return Err(fail("nonce exhausted while grinding block"));
        };
        block.header.nonce = next;
    }
}

/// Returns true when the header hash, read as a little-endian integer, meets
/// the compact bits target (Core `CheckProofOfWork` shape).
fn pow_is_met(bits: u32, hash: &Hash256) -> bool {
    let exponent = usize::try_from(bits >> 24).unwrap_or(usize::MAX);
    let mantissa = bits & 0x00ff_ffff;
    if mantissa == 0 || mantissa & 0x0080_0000 != 0 || exponent > 32 {
        return false;
    }
    let shift = exponent.saturating_sub(3);
    // Little-endian target bytes: mantissa placed `shift` bytes from the
    // least-significant end (mantissa is masked below 2^24, so three bytes).
    let mantissa_le = mantissa.to_le_bytes();
    let mut target = [0_u8; 32];
    for (offset, byte) in mantissa_le.iter().take(3).enumerate() {
        let position = shift + offset;
        if position < 32 {
            target[position] = *byte;
        }
    }
    // Both sides are little-endian 32-byte integers: compare from the most
    // significant byte downward (Core `CheckProofOfWork`).
    let hash_le = hash.to_le_bytes();
    for index in (0..32).rev() {
        match hash_le[index].cmp(&target[index]) {
            std::cmp::Ordering::Less => return true,
            std::cmp::Ordering::Greater => return false,
            std::cmp::Ordering::Equal => {}
        }
    }
    true
}

/// The one-input null-prevout coinbase outpoint (Core `COINBASE_OUTPOINT`).
fn null_prevout() -> OutPoint {
    OutPoint::new(Txid::default(), u32::MAX)
}

/// Minimal script push of a small integer, mirroring rust-bitcoin
/// `Builder::push_int`: `OP_0` for zero, `OP_N` for 1..=16, otherwise a
/// length-prefixed little-endian payload (BIP34 heights).
fn script_push_int(value: i64) -> Vec<u8> {
    match value {
        0 => vec![0x00],
        // `value` is pinned to 1..=16 by the match arm.
        1..=16 => vec![0x50 + u8::try_from(value).unwrap_or_default()],
        _ => {
            let mut payload = Vec::new();
            let mut magnitude = value.unsigned_abs();
            while magnitude > 0 {
                // Low byte only; the shift below consumes it fully.
                payload.push(u8::try_from(magnitude & 0xff).unwrap_or_default());
                magnitude >>= 8;
            }
            let mut out = Vec::with_capacity(payload.len() + 1);
            // A small-int push never exceeds 8 payload bytes.
            out.push(u8::try_from(payload.len()).unwrap_or_default());
            out.extend(payload);
            out
        }
    }
}

/// Native BIP141-style txid merkle fold with the odd-leaf duplication rule.
fn compute_merkle_root(txs: &[Tx]) -> Option<Hash256> {
    if txs.is_empty() {
        return None;
    }
    let mut level: Vec<[u8; 32]> = txs.iter().map(|tx| *tx.txid().as_bytes()).collect();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pos in 0..level.len().div_ceil(2) {
            let left = level[2 * pos];
            let right = level[(2 * pos + 1).min(level.len() - 1)];
            let mut pair = [0_u8; 64];
            pair[..32].copy_from_slice(&left);
            pair[32..].copy_from_slice(&right);
            next.push(*double_sha256(&pair).as_byte_array());
        }
        level = next;
    }
    Some(Hash256::from_le_bytes(&level[0]))
}
