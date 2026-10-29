#![expect(clippy::expect_used, reason = "test assertions")]

use std::sync::Arc;

use anyhow::{Result, anyhow};

use bitcoin_rs_chain::regtest_fixture::{self, REGTEST_BITS};
use bitcoin_rs_mempool::{AdmissionOrigin, FeeEstimator, SubmitOutcome};
use bitcoin_rs_node::state::NodeState;
use bitcoin_rs_node::{Network, NodeConfig};
use bitcoin_rs_primitives::{
    Amount, Block, CompactTarget, Hash256, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut,
    Txid, Witness, unix_time_secs,
};
use bitcoin_rs_rpc::context::ChainAdmissionView;
use bitcoin_rs_script::push_int;
use bitcoin_rs_utxo::contract::{BlockChanges, UtxoAdd};

const BASE_TIME: u32 = 1_296_688_603;
const BLOCK_INTERVAL: u32 = 600;
const REGTEST_SUBSIDY_SATS: u64 = 50 * 100_000_000;
const PARENT_VALUE_SATS: u64 = 50_000;
const HIGH_FEE_SATS: u64 = 30_000;
const LOW_FEE_SATS: u64 = 500;
const REPLACEMENT_FEE_SATS: u64 = 30_000;
const EVICT_THRESHOLD_SAT_PER_KVB: u64 = 10_000;
const HISTORY_FILE: &str = "fee-estimator-history.dat";

fn open_regtest() -> Result<(NodeState, tempfile::TempDir)> {
    let dir = tempfile::tempdir()?;
    let mut config = NodeConfig::default_for_network(Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    let state = NodeState::open(config, None)?;
    Ok((state, dir))
}

fn reopen(config: NodeConfig) -> Result<NodeState> {
    NodeState::open(config, None).map_err(|error| anyhow!("reopen failed: {error}"))
}

fn apply_genesis(state: &NodeState) -> Result<()> {
    state
        .apply_block(&bitcoin_rs_primitives::BlockPayload::from_local(
            Network::Regtest.genesis_block(),
        ))
        .map(|_| ())
        .map_err(|error| anyhow!("genesis apply failed: {error}"))
}

fn fund_utxo(state: &NodeState, parent: Txid, value: u64) -> Result<()> {
    let mut changes = BlockChanges::with_capacity(1, 0);
    changes.add(UtxoAdd::new(
        OutPoint::new(parent, 0),
        TxOut {
            value: Amount::from_sat(value),
            script_pubkey: Script::from_bytes(vec![0x51]),
        },
        false,
        100,
    ));
    bitcoin_rs_utxo::contract::commit_block_changes(
        &state.chainstate().utxo_handle(),
        &changes,
        &Hash256::from_le_bytes(&[0xBB; 32]),
    )
    .map_err(|error| anyhow!("utxo commit failed: {error}"))
}

fn parent_txid(marker: u8) -> Txid {
    Txid::from(Hash256::from_le_bytes(&[marker; 32]))
}

fn spending_tx(parent: Txid, fee_sats: u64, sequence: u32) -> Tx {
    Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(parent, 0),
            script_sig: Script::new(),
            sequence: Sequence::from_consensus(sequence),
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(PARENT_VALUE_SATS - fee_sats),
            script_pubkey: Script::from_bytes(vec![0x6A, 0x04, 0xAA, 0xBB, 0xCC, 0xDD]),
        }],
        lock_time: LockTime::ZERO,
    }
}

fn admit(state: &NodeState, tx: Tx) -> Result<SubmitOutcome> {
    let view = ChainAdmissionView::new(
        state.chainstate().utxo_reader(),
        state.chainstate().applied_tip_reader(),
        state.chainstate().block_tree_reader(),
        Network::Regtest,
    );
    state
        .mempool_gateway()
        .submit_transaction(
            Arc::new(tx),
            AdmissionOrigin::Rpc,
            None,
            unix_time_secs(),
            &view,
        )
        .map_err(|error| anyhow!("admission failed: {error}"))
}

fn mine_and_apply(
    state: &NodeState,
    prev: Hash256,
    height: u32,
    time_salt: u32,
    txs: Vec<Tx>,
) -> Result<Block> {
    let coinbase = Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: Script::from_bytes([push_int(i64::from(height)), push_int(0)].concat()),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(REGTEST_SUBSIDY_SATS),
            script_pubkey: Script::from_bytes(vec![0x51]),
        }],
        lock_time: LockTime::ZERO,
    };
    let mut block = Block {
        header: bitcoin_rs_primitives::Header {
            version: 0x2000_0000,
            prev_blockhash: bitcoin_rs_primitives::BlockHash::from(prev),
            merkle_root: Hash256::from_le_bytes(&[0_u8; 32]),
            time: BASE_TIME
                .saturating_add(BLOCK_INTERVAL.saturating_mul(height))
                .saturating_add(time_salt),
            bits: CompactTarget::from_consensus(REGTEST_BITS),
            nonce: 0,
        },
        txs: std::iter::once(coinbase).chain(txs).collect(),
    };
    block.header.merkle_root = regtest_fixture::merkle_root(&block.txs)
        .ok_or_else(|| anyhow!("block must have a merkle root"))?;
    regtest_fixture::mine_block_to_declared_target(&mut block)?;
    state
        .apply_block(&bitcoin_rs_primitives::BlockPayload::from_local(
            block.clone(),
        ))
        .map_err(|error| anyhow!("apply failed at height {height}: {error}"))?;
    Ok(block)
}

fn assert_matches_declared_semantics(state: &NodeState, shadow: &FeeEstimator) {
    let pool = state.mempool();
    let guard = pool.read();
    assert_eq!(
        guard.estimator_history(),
        shadow.to_history_bytes(),
        "pool estimator state must byte-match the declared-semantics mirror"
    );
    for target in [1_u32, 2, 3, 10, 25] {
        assert_eq!(
            guard.estimate_fee_rate(target),
            shadow.estimate(target),
            "estimate disagreement at target {target}"
        );
    }
}

fn mirror_admitted(shadow: &mut FeeEstimator, state: &NodeState, txid: Txid) {
    let pool = state.mempool();
    let guard = pool.read();
    let entry = guard
        .entry_by_txid(&txid)
        .expect("admitted tx must have a pool entry");
    shadow.tx_entered(txid, entry.fee_rate, entry.height);
}

#[test]
fn empty_or_thin_history_answers_insufficient_data() -> Result<()> {
    let (state, _guard) = open_regtest()?;
    apply_genesis(&state)?;

    let pool = state.mempool();
    assert_eq!(
        pool.read().estimate_fee_rate(1),
        None,
        "no history: target 1 must refuse"
    );
    assert_eq!(
        pool.read().estimate_fee_rate(1008),
        None,
        "no history: beyond-horizon target must refuse"
    );
    assert_eq!(
        pool.read().estimator_last_decayed_height(),
        Some(0),
        "genesis connect must age the estimator to height 0"
    );

    fund_utxo(&state, parent_txid(0x01), PARENT_VALUE_SATS)?;
    let tx = spending_tx(parent_txid(0x01), HIGH_FEE_SATS, 0xffff_ffff);
    admit(&state, tx.clone())?;
    assert!(pool.read().contains_txid(&tx.txid()), "tx must be pooled");
    assert_eq!(
        pool.read().estimate_fee_rate(1),
        None,
        "pending admission alone must not produce an estimate"
    );

    let tip = applied_tip_hash(&state)?;
    mine_and_apply(&state, tip, 1, 0, Vec::new())?;
    assert_eq!(
        pool.read().estimate_fee_rate(1),
        None,
        "one miss must stay insufficient data"
    );
    Ok(())
}

#[test]
fn real_confirmations_qualify_the_estimate() -> Result<()> {
    let (state, _guard) = open_regtest()?;
    apply_genesis(&state)?;
    let pool = state.mempool();

    fund_utxo(&state, parent_txid(0x11), PARENT_VALUE_SATS)?;
    fund_utxo(&state, parent_txid(0x12), PARENT_VALUE_SATS)?;
    fund_utxo(&state, parent_txid(0x13), PARENT_VALUE_SATS)?;
    fund_utxo(&state, parent_txid(0x14), PARENT_VALUE_SATS)?;
    let high = [
        spending_tx(parent_txid(0x11), HIGH_FEE_SATS, 0xffff_ffff),
        spending_tx(parent_txid(0x12), HIGH_FEE_SATS, 0xffff_ffff),
    ];
    let low = [
        spending_tx(parent_txid(0x13), LOW_FEE_SATS, 0xffff_ffff),
        spending_tx(parent_txid(0x14), LOW_FEE_SATS, 0xffff_ffff),
    ];

    let mut shadow = FeeEstimator::new();
    shadow.block_connected(&[], 0);
    for tx in high.iter().chain(low.iter()) {
        let txid = tx.txid();
        admit(&state, tx.clone())?;
        mirror_admitted(&mut shadow, &state, txid);
    }
    assert_eq!(pool.read().len(), 4, "all four admissions must be pooled");
    let high_rate = pool
        .read()
        .entry_by_txid(&high[0].txid())
        .expect("high tier must be pooled")
        .fee_rate;
    let low_rate = pool
        .read()
        .entry_by_txid(&low[0].txid())
        .expect("low tier must be pooled")
        .fee_rate;
    assert_matches_declared_semantics(&state, &shadow);

    let tip = applied_tip_hash(&state)?;
    mine_and_apply(&state, tip, 1, 0, high.to_vec())?;
    shadow.block_connected(&txids(&high), 1);
    assert_matches_declared_semantics(&state, &shadow);

    let estimate_short = pool
        .read()
        .estimate_fee_rate(1)
        .expect("two one-block confirmations must qualify target 1");
    assert!(
        estimate_short.as_sat_per_kvb() > low_rate && estimate_short.as_sat_per_kvb() <= high_rate,
        "target 1 must sit in the high tier's bucket, got {} sat/kvB \
         (low {low_rate}, high {high_rate})",
        estimate_short.as_sat_per_kvb()
    );
    let estimate_long = pool
        .read()
        .estimate_fee_rate(2)
        .expect("confirmed-in-one history must qualify target 2");
    assert!(
        estimate_long < estimate_short,
        "longer horizon must demand a lower rate: {} vs {}",
        estimate_long.as_sat_per_kvb(),
        estimate_short.as_sat_per_kvb()
    );
    assert_eq!(
        pool.read().estimator_last_decayed_height(),
        Some(1),
        "block 1 must age the estimator"
    );

    let tip = applied_tip_hash(&state)?;
    mine_and_apply(&state, tip, 2, 0, low.to_vec())?;
    shadow.block_connected(&txids(&low), 2);
    assert_matches_declared_semantics(&state, &shadow);
    assert_eq!(pool.read().len(), 0, "both tiers must be confirmed out");
    assert_eq!(
        pool.read().estimator_last_decayed_height(),
        Some(2),
        "block 2 must age the estimator"
    );
    assert_eq!(
        pool.read().estimate_fee_rate(1),
        Some(estimate_short),
        "target 1 must keep requiring the high tier"
    );
    Ok(())
}

#[test]
fn replacement_untracks_victim_without_false_confirmation() -> Result<()> {
    let (state, _guard) = open_regtest()?;
    apply_genesis(&state)?;
    let pool = state.mempool();

    fund_utxo(&state, parent_txid(0x21), PARENT_VALUE_SATS)?;
    let victim = spending_tx(parent_txid(0x21), LOW_FEE_SATS, 0xffff_fffd);
    let replacement = spending_tx(parent_txid(0x21), REPLACEMENT_FEE_SATS, 0xffff_fffd);

    let mut shadow = FeeEstimator::new();
    shadow.block_connected(&[], 0);
    admit(&state, victim.clone())?;
    mirror_admitted(&mut shadow, &state, victim.txid());
    assert!(
        pool.read().contains_txid(&victim.txid()),
        "victim must pool"
    );

    admit(&state, replacement.clone())?;
    mirror_admitted(&mut shadow, &state, replacement.txid());
    shadow.tx_left(&victim.txid());
    assert_matches_declared_semantics(&state, &shadow);
    assert!(
        !pool.read().contains_txid(&victim.txid()),
        "victim must leave the pool on replacement"
    );
    assert!(
        pool.read().contains_txid(&replacement.txid()),
        "replacement must pool"
    );

    let tip = applied_tip_hash(&state)?;
    mine_and_apply(&state, tip, 1, 0, vec![replacement.clone()])?;
    shadow.block_connected(&[replacement.txid()], 1);
    assert_matches_declared_semantics(&state, &shadow);
    assert!(
        pool.read().estimate_fee_rate(1).is_none(),
        "one confirmation is below the decayed-observation floor"
    );
    Ok(())
}

#[test]
fn eviction_untracks_without_false_confirmation() -> Result<()> {
    let (state, _guard) = open_regtest()?;
    apply_genesis(&state)?;
    let pool = state.mempool();

    fund_utxo(&state, parent_txid(0x31), PARENT_VALUE_SATS)?;
    fund_utxo(&state, parent_txid(0x32), PARENT_VALUE_SATS)?;
    let evicted = spending_tx(parent_txid(0x31), LOW_FEE_SATS, 0xffff_ffff);
    let kept = spending_tx(parent_txid(0x32), HIGH_FEE_SATS, 0xffff_ffff);

    let mut shadow = FeeEstimator::new();
    shadow.block_connected(&[], 0);
    admit(&state, evicted.clone())?;
    mirror_admitted(&mut shadow, &state, evicted.txid());
    admit(&state, kept.clone())?;
    mirror_admitted(&mut shadow, &state, kept.txid());

    let _ = state
        .mempool_gateway()
        .evict_below_fee_rate(AdmissionOrigin::Rpc, EVICT_THRESHOLD_SAT_PER_KVB);
    shadow.tx_left(&evicted.txid());
    assert_matches_declared_semantics(&state, &shadow);
    assert!(
        !pool.read().contains_txid(&evicted.txid()),
        "low-tier tx must be evicted"
    );
    assert!(
        pool.read().contains_txid(&kept.txid()),
        "high-tier tx must stay"
    );

    let tip = applied_tip_hash(&state)?;
    mine_and_apply(&state, tip, 1, 0, vec![kept.clone()])?;
    shadow.block_connected(&[kept.txid()], 1);
    assert_matches_declared_semantics(&state, &shadow);
    assert!(
        pool.read().estimate_fee_rate(1).is_none(),
        "one confirmation is below the decayed-observation floor"
    );
    Ok(())
}

#[test]
fn reorg_reconfirm_records_exactly_one_observation() -> Result<()> {
    let (state, _guard) = open_regtest()?;
    apply_genesis(&state)?;
    let pool = state.mempool();

    fund_utxo(&state, parent_txid(0x41), PARENT_VALUE_SATS)?;
    fund_utxo(&state, parent_txid(0x42), PARENT_VALUE_SATS)?;
    let txs = [
        spending_tx(parent_txid(0x41), HIGH_FEE_SATS, 0xffff_ffff),
        spending_tx(parent_txid(0x42), HIGH_FEE_SATS, 0xffff_ffff),
    ];
    for tx in &txs {
        admit(&state, tx.clone())?;
    }

    let genesis = applied_tip_hash(&state)?;
    let block1 = mine_and_apply(&state, genesis, 1, 0, txs.to_vec())?;
    let estimate_before = pool
        .read()
        .estimate_fee_rate(1)
        .expect("two same-bucket confirmations must qualify target 1");
    let bytes_before = pool.read().estimator_history();

    bitcoin_rs_node::reorg::invalidate_block(
        &state.chainstate(),
        &state.chain_followers(),
        Hash256::from(block1.block_hash()),
    )
    .map_err(|error| anyhow!("invalidate_block failed: {error}"))?;
    for tx in &txs {
        assert!(
            pool.read().contains_txid(&tx.txid()),
            "reconsideration must re-admit {}",
            tx.txid()
        );
    }
    assert_eq!(
        pool.read().estimate_fee_rate(1),
        Some(estimate_before),
        "reorg must preserve recorded confirmations, not wipe them"
    );

    let sibling = mine_and_apply(&state, genesis, 1, 1, txs.to_vec())?;
    assert_ne!(
        sibling.block_hash(),
        block1.block_hash(),
        "sibling block must be a distinct block"
    );
    assert_eq!(pool.read().len(), 0, "re-confirmed txs must leave the pool");
    assert_eq!(
        pool.read().estimate_fee_rate(1),
        Some(estimate_before),
        "re-confirm must not change the estimate: one observation, not two"
    );
    assert_eq!(
        pool.read().estimator_history(),
        bytes_before,
        "re-confirm must leave the estimator state byte-identical"
    );
    Ok(())
}

#[test]
fn restart_adopts_persisted_estimator_history() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let mut config = NodeConfig::default_for_network(Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();

    let state = NodeState::open(config.clone(), None)?;
    apply_genesis(&state)?;
    let pool = state.mempool();
    for marker in [0x51_u8, 0x52] {
        fund_utxo(&state, parent_txid(marker), PARENT_VALUE_SATS)?;
    }
    let txs = [
        spending_tx(parent_txid(0x51), HIGH_FEE_SATS, 0xffff_ffff),
        spending_tx(parent_txid(0x52), HIGH_FEE_SATS, 0xffff_ffff),
    ];
    for tx in &txs {
        admit(&state, tx.clone())?;
    }
    let tip = applied_tip_hash(&state)?;
    mine_and_apply(&state, tip, 1, 0, txs.to_vec())?;

    let estimate_before = pool
        .read()
        .estimate_fee_rate(1)
        .expect("seeded confirmations must qualify target 1");
    let bytes_before = pool.read().estimator_history();
    let decayed_before = pool.read().estimator_last_decayed_height();

    let history_path = config.data_dir.join(HISTORY_FILE);
    std::fs::write(&history_path, &bytes_before)?;

    drop(state);
    let reopened = reopen(config)?;
    let pool = reopened.mempool();
    assert_eq!(
        pool.read().estimate_fee_rate(1),
        Some(estimate_before),
        "reopened node must answer with the persisted estimate"
    );
    assert_eq!(
        pool.read().estimator_last_decayed_height(),
        decayed_before,
        "reopened node must restore the decayed height"
    );
    assert_eq!(
        pool.read().estimator_history(),
        bytes_before,
        "reopened estimator state must be byte-identical (no decay while idle)"
    );
    Ok(())
}

#[test]
fn corrupt_history_file_degrades_to_insufficient_data() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let mut config = NodeConfig::default_for_network(Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();

    let state = NodeState::open(config.clone(), None)?;
    apply_genesis(&state)?;
    let pool = state.mempool();
    for marker in [0x61_u8, 0x62] {
        fund_utxo(&state, parent_txid(marker), PARENT_VALUE_SATS)?;
    }
    let txs = [
        spending_tx(parent_txid(0x61), HIGH_FEE_SATS, 0xffff_ffff),
        spending_tx(parent_txid(0x62), HIGH_FEE_SATS, 0xffff_ffff),
    ];
    for tx in &txs {
        admit(&state, tx.clone())?;
    }
    let tip = applied_tip_hash(&state)?;
    mine_and_apply(&state, tip, 1, 0, txs.to_vec())?;
    assert!(pool.read().estimate_fee_rate(1).is_some());
    drop(state);

    let history_path = config.data_dir.join(HISTORY_FILE);
    let corrupt: Vec<u8> = std::iter::repeat_n(0xFF_u8, 128).collect();
    std::fs::write(&history_path, &corrupt)?;

    let reopened = reopen(config)?;
    let pool = reopened.mempool();
    assert_eq!(
        pool.read().estimate_fee_rate(1),
        None,
        "corrupt history must degrade to insufficient data"
    );
    assert_eq!(
        std::fs::read(&history_path)?,
        corrupt,
        "a rejected payload must stay in place for its owner"
    );
    fund_utxo(&reopened, parent_txid(0x63), PARENT_VALUE_SATS)?;
    let fresh = spending_tx(parent_txid(0x63), HIGH_FEE_SATS, 0xffff_ffff);
    admit(&reopened, fresh.clone())?;
    assert!(
        pool.read().contains_txid(&fresh.txid()),
        "degraded node must keep admitting"
    );
    Ok(())
}

fn txids(txs: &[Tx]) -> Vec<Txid> {
    txs.iter().map(Tx::txid).collect()
}

fn applied_tip_hash(state: &NodeState) -> Result<Hash256> {
    state
        .chainstate()
        .applied_tip_snapshot()
        .map(|tip| tip.hash)
        .ok_or_else(|| anyhow!("applied tip must exist"))
}
