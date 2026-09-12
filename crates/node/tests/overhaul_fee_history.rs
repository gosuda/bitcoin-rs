//! #641 / T23 acceptance: fee estimates come from real admission and
//! confirmation history, exercised through production wiring.
//!
//! Every leg drives the node's real surfaces: transactions enter through the
//! one shared [`bitcoin_rs_mempool::MempoolGateway`] exactly like RPC ingress
//! (`crates/node/src/tx_ingress.rs`), confirmations happen when ordinary
//! block validation connects a block containing them
//! (`crates/node/src/apply/connect.rs` → `remove_for_block`), replacements go
//! through gateway admission's BIP125 path, evictions through
//! `evict_below_fee_rate`, the reorg leg through `reorg::invalidate_block`
//! with its reconsideration walk, and restart through `NodeState::open`
//! adopting the owner-local `fee-estimator-history.dat` file.
//!
//! The declared estimator semantics are mirrored with the public
//! [`FeeEstimator`] event API (`tx_entered` / `tx_left` / `block_connected`)
//! and asserted byte-for-byte against the pool's persisted estimator state
//! (`Mempool::estimator_history`, deterministic by contract). A false
//! confirmation, a lost untrack, or a reorg double-count changes those bytes,
//! so each leg's invariant fails loudly instead of passing on a plausible
//! estimate value.
//!
//! Insufficient data answers `None` — the exact condition the RPC's
//! `estimatesmartfee` maps to `errors: ["Insufficient data or no feerate
//! found"]` with the fee rate omitted (`crates/rpc/src/handlers/util.rs`).

#![expect(clippy::expect_used, reason = "test assertions")]

use std::sync::Arc;

use anyhow::{Result, anyhow, bail};

use bitcoin_rs_mempool::{AdmissionOrigin, FeeEstimator, SubmitOutcome};
use bitcoin_rs_node::state::NodeState;
use bitcoin_rs_node::{Network, NodeConfig};
use bitcoin_rs_primitives::{
    Amount, Block, CompactTarget, Hash256, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut,
    Txid, Witness, encode::double_sha256,
};
use bitcoin_rs_rpc::context::ChainAdmissionView;
use bitcoin_rs_utxo::{BlockChanges, UtxoAdd};

/// Header timestamp base for the regtest fixture chain.
const BASE_TIME: u32 = 1_296_688_603;
/// Seconds between fixture blocks; also spaces admission timestamps.
const BLOCK_INTERVAL: u32 = 600;
/// Regtest difficulty: one hash attempt meets it.
const REGTEST_BITS: u32 = 0x207f_ffff;
/// Regtest block subsidy paid to every fixture coinbase.
const REGTEST_SUBSIDY_SATS: u64 = 50 * 100_000_000;
/// Input value of every funded fixture parent.
const PARENT_VALUE_SATS: u64 = 50_000;
/// High fee tier: well above the min-relay floor, its own bucket.
const HIGH_FEE_SATS: u64 = 30_000;
/// Low fee tier: above min relay, far below the high tier.
const LOW_FEE_SATS: u64 = 500;
/// Fee the replacement pays over the victim: clears every BIP125 rule.
const REPLACEMENT_FEE_SATS: u64 = 30_000;
/// Eviction threshold between the two tiers (sat/kvB).
const EVICT_THRESHOLD_SAT_PER_KVB: u64 = 10_000;
/// The estimator's owner-local datadir file (crates/node/src/fee_history.rs).
const HISTORY_FILE: &str = "fee-estimator-history.dat";

// ---------------------------------------------------------------------------
// Node and chain fixtures
// ---------------------------------------------------------------------------

/// Opens an isolated regtest `NodeState`; the guard keeps the data directory
/// alive for the whole test body.
fn open_regtest() -> Result<(NodeState, tempfile::TempDir)> {
    let dir = tempfile::tempdir()?;
    let mut config = NodeConfig::default_for_network(Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    let state = NodeState::open(config, None)?;
    Ok((state, dir))
}

/// Reopens a `NodeState` over an existing datadir (restart legs).
fn reopen(config: NodeConfig) -> Result<NodeState> {
    NodeState::open(config, None).map_err(|error| anyhow!("reopen failed: {error}"))
}

fn apply_genesis(state: &NodeState) -> Result<()> {
    state
        .apply_block(&Network::Regtest.genesis_block())
        .map(|_| ())
        .map_err(|error| anyhow!("genesis apply failed: {error}"))
}

/// Funds one spendable parent output directly in the node's real `UtxoSet`
/// (the same seam the apply path writes through), so spends pass the
/// missing-inputs check.
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
    state
        .utxo()
        .commit_block(&changes, &Hash256::from_le_bytes(&[0xBB; 32]))
        .map_err(|error| anyhow!("utxo commit failed: {error}"))
}

/// Deterministic funded parent txid for a marker byte.
fn parent_txid(marker: u8) -> Txid {
    Txid::from(Hash256::from_le_bytes(&[marker; 32]))
}

/// One-input, one-output spend of a funded parent; `fee_sats` is the fee and
/// `sequence` controls BIP125 signaling (`0xffff_fffd` signals replaceable,
/// relative locktime disabled).
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
        lock_time: LockTime::from_consensus(0),
    }
}

/// Admits `tx` through the node's shared gateway exactly like production RPC
/// ingress.
fn admit(state: &NodeState, tx: Tx, time: u64) -> Result<SubmitOutcome> {
    let utxo = state.utxo();
    let applied_tip = state.applied_tip();
    let block_tree = state.block_tree();
    let view = ChainAdmissionView::new(&utxo, &applied_tip, &block_tree);
    state
        .mempool_gateway()
        .submit_transaction(Arc::new(tx), AdmissionOrigin::Rpc, None, time, &view)
        .map_err(|error| anyhow!("admission failed: {error}"))
}

/// Mines and applies the regtest block at `height` over `prev`: coinbase plus
/// `txs`, through ordinary validation. `time_salt` keeps sibling blocks that
/// carry the same transactions distinct by hash.
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
            previous_output: null_prevout(),
            // BIP34 height push plus one pad byte: consensus requires a
            // 2..=100 byte coinbase scriptSig.
            script_sig: Script::from_bytes(
                [script_push_int(i64::from(height)), script_push_int(0)].concat(),
            ),
            sequence: Sequence::from_consensus(0xffff_ffff),
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(REGTEST_SUBSIDY_SATS),
            script_pubkey: Script::from_bytes(vec![0x51]),
        }],
        lock_time: LockTime::from_consensus(0),
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
    block.header.merkle_root =
        compute_merkle_root(&block.txs).ok_or_else(|| anyhow!("block must have a merkle root"))?;
    grind_pow(&mut block)?;
    state
        .apply_block(&block)
        .map_err(|error| anyhow!("apply failed at height {height}: {error}"))?;
    Ok(block)
}

fn null_prevout() -> OutPoint {
    OutPoint::new(Txid::default(), u32::MAX)
}

/// Minimal script push of a small integer (BIP34 heights): `OP_0` for zero,
/// `OP_N` for 1..=16, otherwise a length-prefixed little-endian payload.
fn script_push_int(value: i64) -> Vec<u8> {
    match value {
        0 => vec![0x00],
        1..=16 => vec![0x50 + u8::try_from(value).unwrap_or_default()],
        _ => {
            let payload = value.to_le_bytes();
            let len = payload
                .iter()
                .rposition(|byte| *byte != 0)
                .map_or(1, |position| position + 1);
            let mut out = vec![u8::try_from(len).unwrap_or(u8::MAX)];
            out.extend_from_slice(&payload[..len]);
            out
        }
    }
}

fn grind_pow(block: &mut Block) -> Result<()> {
    loop {
        if pow_is_met(
            block.header.bits.to_consensus(),
            &block.header.compute_hash().into(),
        ) {
            return Ok(());
        }
        let Some(next) = block.header.nonce.checked_add(1) else {
            bail!("nonce exhausted while grinding block");
        };
        block.header.nonce = next;
    }
}

/// True when the header hash, read as a little-endian integer, meets the
/// compact bits target (Core `CheckProofOfWork` shape).
fn pow_is_met(bits: u32, hash: &Hash256) -> bool {
    let exponent = usize::try_from(bits >> 24).unwrap_or(usize::MAX);
    let mantissa = bits & 0x00ff_ffff;
    if mantissa == 0 || mantissa & 0x0080_0000 != 0 || exponent > 32 {
        return false;
    }
    let shift = exponent.saturating_sub(3);
    let mantissa_le = mantissa.to_le_bytes();
    let mut target = [0_u8; 32];
    for (offset, byte) in mantissa_le.iter().take(3).enumerate() {
        let position = shift + offset;
        if position < 32 {
            target[position] = *byte;
        }
    }
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

// ---------------------------------------------------------------------------
// Declared-semantics mirror
// ---------------------------------------------------------------------------

/// Asserts the pool's estimator state byte-matches `shadow` — the declared
/// semantics replayed through the public event API — and that both answer
/// identically at every confirmation target.
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

/// Mirrors one admission into `shadow` using the actual `MempoolEntry` fields
/// the pool fed the estimator (`entry.fee_rate`, `entry.height`).
fn mirror_admitted(shadow: &mut FeeEstimator, state: &NodeState, txid: Txid) {
    let pool = state.mempool();
    let guard = pool.read();
    let entry = guard
        .entry_by_txid(&txid)
        .expect("admitted tx must have a pool entry");
    shadow.tx_entered(txid, entry.fee_rate, entry.height);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

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

    // A real admission at the high tier still cannot fabricate an estimate.
    fund_utxo(&state, parent_txid(0x01), PARENT_VALUE_SATS)?;
    let tx = spending_tx(parent_txid(0x01), HIGH_FEE_SATS, 0xffff_ffff);
    admit(&state, tx.clone(), u64::from(BASE_TIME))?;
    assert!(pool.read().contains_txid(&tx.txid()), "tx must be pooled");
    assert_eq!(
        pool.read().estimate_fee_rate(1),
        None,
        "pending admission alone must not produce an estimate"
    );

    // Connected without the tx, the pending tx misses target 1: one failure
    // is still insufficient data, never a fabricated rate.
    let tip = applied_tip_hash(&state)?;
    mine_and_apply(&state, tip, 1, 0, Vec::new())?;
    assert_eq!(
        pool.read().estimate_fee_rate(1),
        None,
        "one miss must stay insufficient data"
    );
    Ok(())
}

/// Real admitted-and-confirmed history qualifies the estimate: two fee tiers
/// admitted through the shared gateway, confirmed by ordinary block
/// validation, with the short horizon demanding a higher rate than the long
/// one — exactly the declared semantics, byte-for-byte.
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
    // `apply_genesis` connected the genesis block, so the estimator has aged
    // to height 0 even before any transactions are admitted.
    shadow.block_connected(&[], 0);
    for tx in high.iter().chain(low.iter()) {
        let txid = tx.txid();
        admit(&state, tx.clone(), u64::from(BASE_TIME))?;
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

    // Block 1 confirms the high tier; the low tier misses target 1.
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

    // Block 2 confirms the low tier: it missed target 1 and made target 2.
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
    // The short horizon still remembers the low tier's miss.
    assert_eq!(
        pool.read().estimate_fee_rate(1),
        Some(estimate_short),
        "target 1 must keep requiring the high tier"
    );
    Ok(())
}

/// A BIP125 replacement untracks the victim (no false confirmation, no
/// phantom failure) and the replacement's own confirmation is the only
/// success ever recorded.
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
    admit(&state, victim.clone(), u64::from(BASE_TIME))?;
    mirror_admitted(&mut shadow, &state, victim.txid());
    assert!(
        pool.read().contains_txid(&victim.txid()),
        "victim must pool"
    );

    admit(&state, replacement.clone(), u64::from(BASE_TIME))?;
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

    // Only the replacement confirms; a false victim confirmation would put a
    // second success and a confirmed_at record into the estimator bytes.
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

/// A fee-policy eviction untracks the evicted transaction: it neither stays
/// pending (which would record a miss) nor counts as confirmed.
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
    admit(&state, evicted.clone(), u64::from(BASE_TIME))?;
    mirror_admitted(&mut shadow, &state, evicted.txid());
    admit(&state, kept.clone(), u64::from(BASE_TIME))?;
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

/// Reorg: invalidating the confirming block reconsiders its transactions back
/// into the pool with the recorded confirmations preserved, and re-confirming
/// them in a sibling block records exactly one observation — not two.
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
        admit(&state, tx.clone(), u64::from(BASE_TIME))?;
    }

    let genesis = applied_tip_hash(&state)?;
    let block1 = mine_and_apply(&state, genesis, 1, 0, txs.to_vec())?;
    let estimate_before = pool
        .read()
        .estimate_fee_rate(1)
        .expect("two same-bucket confirmations must qualify target 1");
    let bytes_before = pool.read().estimator_history();

    // Invalidate block 1: the reconsideration walk re-admits its two
    // transactions and the estimator's recorded confirmations survive.
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

    // Re-confirm the same transactions in a sibling block: the dedup record
    // must keep one physical confirmation one recorded success, so the whole
    // estimator state returns byte-identically.
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

/// Restart adopts the owner-local history file: the reopened node answers
/// with the exact persisted estimate and state bytes.
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
        admit(&state, tx.clone(), u64::from(BASE_TIME))?;
    }
    let tip = applied_tip_hash(&state)?;
    mine_and_apply(&state, tip, 1, 0, txs.to_vec())?;

    let estimate_before = pool
        .read()
        .estimate_fee_rate(1)
        .expect("seeded confirmations must qualify target 1");
    let bytes_before = pool.read().estimator_history();
    let decayed_before = pool.read().estimator_last_decayed_height();

    // Publish the owner-local history exactly as the owner would at shutdown.
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

/// A corrupt history file degrades to insufficient data: the node starts, the
/// rejected file stays in place, and admission still works.
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
        admit(&state, tx.clone(), u64::from(BASE_TIME))?;
    }
    let tip = applied_tip_hash(&state)?;
    mine_and_apply(&state, tip, 1, 0, txs.to_vec())?;
    assert!(pool.read().estimate_fee_rate(1).is_some());
    drop(state);

    // Corrupt the owner-local file out of the owner's hands.
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
    // The degraded node is fully operational: a fresh admission still tracks.
    fund_utxo(&reopened, parent_txid(0x63), PARENT_VALUE_SATS)?;
    let fresh = spending_tx(parent_txid(0x63), HIGH_FEE_SATS, 0xffff_ffff);
    admit(&reopened, fresh.clone(), u64::from(BASE_TIME) + 2)?;
    assert!(
        pool.read().contains_txid(&fresh.txid()),
        "degraded node must keep admitting"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Small shared helpers
// ---------------------------------------------------------------------------

fn txids(txs: &[Tx]) -> Vec<Txid> {
    txs.iter().map(Tx::txid).collect()
}

fn applied_tip_hash(state: &NodeState) -> Result<Hash256> {
    state
        .applied_tip()
        .load_full()
        .map(|tip| tip.hash)
        .ok_or_else(|| anyhow!("applied tip must exist"))
}
