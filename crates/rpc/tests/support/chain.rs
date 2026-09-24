//! Deterministic regtest seed chain, mined through ordinary validation.
//!
//! The blocks are built natively with trivial regtest proof of work (grinding
//! the nonce against the minimum target), each coinbase paying the
//! anyone-can-spend `OP_TRUE` output, and applied through the real
//! `NodeState::apply_block` path. Nothing here fakes mining evidence: the
//! chain exists so the replay has a real, reproducible tip to bind
//! chain-bound keys to.

use super::{GateResult, fail};
use bitcoin_rs_chain::regtest_fixture;
use bitcoin_rs_node::{Network, NodeConfig, state::NodeState};
use bitcoin_rs_primitives::{
    Amount, Block, CompactTarget, Hash256, LockTime, OutPoint, Sequence, Tx, TxIn, TxOut, Txid,
    Witness,
};

/// Block the seed chain starts from; one minute after the genesis stamp, so
/// mediantime arithmetic matches Core's regtest spacing.
pub(crate) const SEED_BASE_TIME: u32 = 1_296_688_603;
/// Seconds between seed blocks; Core's regtest spacing.
pub(crate) const SEED_BLOCK_INTERVAL: u32 = 600;
/// The never-retargeting regtest minimum target.
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
                script_sig: [script_push_int(i64::from(height)), script_push_int(0)]
                    .concat()
                    .into(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(REGTEST_SUBSIDY_SATS),
                script_pubkey: vec![0x51].into(),
            }],
            lock_time: LockTime::ZERO,
        };
        let mut block = Block {
            header: bitcoin_rs_primitives::Header {
                version: 0x2000_0000,
                prev_blockhash: bitcoin_rs_primitives::BlockHash::from(tip.hash),
                merkle_root: Hash256::from_le_bytes(&[0_u8; 32]),
                time: SEED_BASE_TIME.saturating_add(SEED_BLOCK_INTERVAL.saturating_mul(height)),
                bits: CompactTarget::from_consensus(regtest_fixture::REGTEST_BITS),
                nonce: 0,
            },
            txs: vec![coinbase],
        };
        block.header.merkle_root = regtest_fixture::merkle_root(&block.txs)
            .ok_or_else(|| fail("seed block must have a merkle root"))?;
        regtest_fixture::mine_block_to_declared_target(&mut block).map_err(fail)?;
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
    let applied = state.chainstate().applied_tip_handle();
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
