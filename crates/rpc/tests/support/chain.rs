//! Deterministic regtest seed chain, mined through ordinary validation.

use super::{GateResult, fail};
use bitcoin_rs_chain::regtest_fixture;
use bitcoin_rs_node::{Network, NodeConfig, state::NodeState};
use bitcoin_rs_primitives::{
    Amount, Block, CompactTarget, Hash256, LockTime, OutPoint, Sequence, Tx, TxIn, TxOut, Witness,
};
use bitcoin_rs_script::push_int;

/// Block the seed chain starts from; one minute after the genesis stamp, so
/// mediantime arithmetic matches Core's regtest spacing.
pub(crate) const SEED_BASE_TIME: u32 = 1_296_688_603;
/// Seconds between seed blocks; Core's regtest spacing.
pub(crate) const SEED_BLOCK_INTERVAL: u32 = 600;
pub(crate) const REGTEST_SUBSIDY_SATS: u64 = 50 * 100_000_000;

pub(crate) fn apply_genesis(state: &NodeState) -> GateResult<()> {
    let genesis = Network::Regtest.genesis_block();
    state
        .apply_block(&bitcoin_rs_primitives::BlockPayload::from_local(genesis))
        .map_err(fail)?;
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SeedChain {
    pub tip_height: u32,
    pub tip_hash: Hash256,
}

pub(crate) fn seed_chain(state: &NodeState, count: u32) -> GateResult<SeedChain> {
    let mut tip = current_tip(state)?;
    for height in 1..=count {
        let coinbase = Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: [push_int(i64::from(height)), push_int(0)].concat().into(),
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
        state
            .apply_block(&bitcoin_rs_primitives::BlockPayload::from_local(block))
            .map_err(fail)?;
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

pub(crate) fn current_tip(state: &NodeState) -> GateResult<bitcoin_rs_chain::TipSnapshot> {
    let Some(tip) = state.chainstate().applied_tip_snapshot() else {
        return Err(fail("applied tip must exist"));
    };
    Ok((*tip).clone())
}

#[must_use]
pub(crate) fn regtest_config(dir: &std::path::Path) -> NodeConfig {
    let mut config = NodeConfig::default_for_network(Network::Regtest);
    config.data_dir = dir.to_path_buf();
    config.p2p.listen.clear();
    config
}
