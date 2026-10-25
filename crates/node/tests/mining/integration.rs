use std::sync::Arc;

use anyhow::Result;
use bitcoin::hex::DisplayHex;
use bitcoin_rs_mempool::{MempoolObserver, MutationEnvelope, MutationOutcome};
use bitcoin_rs_primitives::{
    Amount, Hash256, LockTime, OutPoint, Sequence, Tx, TxIn, TxOut, Witness, consensus_bytes,
    encode::double_sha256,
};
use parking_lot::Mutex;
use sonic_rs::{JsonContainerTrait as _, JsonValueTrait, json};

use super::support::{
    LongPollId, MEMPOOL_TX_FEE_SATS, PRIORITY_DELTA_SATS, PROMPT, REGTEST_SUBSIDY_SATS,
    SEED_BLOCKS, WITNESS_RESERVED, admit_to_mempool, apply_genesis, assemble_from_template,
    assemble_regtest_block, compute_witness_merkle_root, current_tip, live_long_poll_id,
    mine_regtest_block, mining_handler, open_regtest, p2sh_true_output, p2sh_true_spend_script_sig,
    priority_fixture, required_str, required_u64, seed_chain, seed_coinbase_spend,
    seed_coinbase_spend_with_fee, txid_strings,
};

#[test]
fn template_renders_coinbase_subsidy_plus_fees_and_bip22_fields() -> Result<()> {
    let (state, _guard) = open_regtest()?;
    apply_genesis(&state)?;
    let seed_tip_hash = seed_chain(&state, SEED_BLOCKS)?;

    // A spend of the height-1 seed coinbase matures exactly at height 101.
    let mempool_tx = seed_coinbase_spend();
    admit_to_mempool(&state, &mempool_tx)?;

    let handler = mining_handler(&state);
    let template = handler.dispatch("getblocktemplate", &json!([{"rules": ["segwit"]}]))?;

    // 1. Exact reward calculation: subsidy + all mempool transaction fees.
    assert_eq!(
        required_u64(&template, "coinbasevalue")?,
        REGTEST_SUBSIDY_SATS + MEMPOOL_TX_FEE_SATS,
        "coinbasevalue must be subsidy plus selected fees"
    );

    let template_txs = template
        .get("transactions")
        .and_then(|entry| entry.as_array())
        .map_or(&[][..], |entries| entries.as_slice());
    assert_eq!(template_txs.len(), 1, "the mempool tx must be selected");

    // 2. Exact transaction weight match (not just > 0).
    assert_eq!(
        required_u64(&template_txs[0], "weight")?,
        mempool_tx.weight(),
        "rendered weight must match the transaction weight"
    );
    assert_eq!(required_u64(&template_txs[0], "sigops")?, 0);

    // 3. Essential BIP22 mutable and capability sets for external miner interop.
    let mutable = template
        .get("mutable")
        .and_then(|v| v.as_array())
        .map_or(&[][..], |a| a.as_slice());
    for expected in ["time", "transactions", "prevblock"] {
        assert!(
            mutable.iter().any(|v| v.as_str() == Some(expected)),
            "mutable must contain {expected}"
        );
    }
    let capabilities = template
        .get("capabilities")
        .and_then(|v| v.as_array())
        .map_or(&[][..], |a| a.as_slice());
    for expected in ["proposal", "longpoll"] {
        assert!(
            capabilities.iter().any(|v| v.as_str() == Some(expected)),
            "capabilities must contain {expected}"
        );
    }

    // 4. BIP22 header & constraint fields (preserves coverage from deleted e2e::block_template_shape).
    assert_eq!(
        required_str(&template, "previousblockhash")?,
        seed_tip_hash.to_string_be()
    );
    assert_eq!(
        required_u64(&template, "height")?,
        u64::from(SEED_BLOCKS + 1)
    );
    assert_eq!(required_str(&template, "bits")?, "207fffff");
    assert_eq!(
        required_str(&template, "target")?,
        "7fffff0000000000000000000000000000000000000000000000000000000000"
    );
    assert_eq!(required_str(&template, "noncerange")?, "00000000ffffffff");
    assert_eq!(required_u64(&template, "sigoplimit")?, 80_000);
    assert_eq!(required_u64(&template, "sizelimit")?, 4_000_000);
    assert_eq!(required_u64(&template, "weightlimit")?, 4_000_000);
    assert!(required_u64(&template, "mintime")? <= required_u64(&template, "curtime")?);
    let rules = template
        .get("rules")
        .and_then(|v| v.as_array())
        .map_or(&[][..], |a| a.as_slice());
    assert!(
        rules.iter().any(|x| x.as_str() == Some("!segwit")),
        "segwit is mandatory"
    );

    // 5. BIP141 witness commitment derivation and longpollid.
    assert_template_witness_commitment(&template, &mempool_tx)?;
    let long_poll_id = required_str(&template, "longpollid")?;
    assert_eq!(
        LongPollId::parse(&long_poll_id)?.tip,
        seed_tip_hash.to_string_be(),
        "longpollid starts with the applied tip hash"
    );
    assert_eq!(
        long_poll_id,
        live_long_poll_id(&state)?,
        "longpollid is {{tip}}{{mempool_sequence}}[:{{fee_delta_sequence}}] of the live pool"
    );

    // A fee-only RPC change refreshes the cached identity without moving membership.
    let sequence = state.mempool().read().sequence_number();
    assert_eq!(
        handler
            .dispatch(
                "prioritisetransaction",
                &json!([mempool_tx.txid().to_string(), 0, 100_000])
            )?
            .as_bool(),
        Some(true)
    );
    assert_eq!(state.mempool().read().sequence_number(), sequence);
    let refreshed = handler.dispatch("getblocktemplate", &json!([{"rules": ["segwit"]}]))?;
    assert_ne!(required_str(&refreshed, "longpollid")?, long_poll_id);
    assert_eq!(
        required_u64(&refreshed, "coinbasevalue")?,
        REGTEST_SUBSIDY_SATS + MEMPOOL_TX_FEE_SATS
    );

    Ok(())
}

fn assert_template_witness_commitment(template: &sonic_rs::Value, mempool_tx: &Tx) -> Result<()> {
    let commitment = required_str(template, "default_witness_commitment")?;
    assert!(
        commitment.starts_with("6a24aa21a9ed"),
        "default witness commitment carries BIP141 prefix"
    );
    let expected_root = compute_witness_merkle_root(std::slice::from_ref(mempool_tx))
        .ok_or_else(|| anyhow::anyhow!("single-tx witness merkle root must exist"))?;
    let mut commitment_input = [0_u8; 64];
    commitment_input[..32].copy_from_slice(&expected_root.to_le_bytes());
    commitment_input[32..].copy_from_slice(&WITNESS_RESERVED);
    let expected_commitment = double_sha256(&commitment_input).to_le_bytes();
    assert_eq!(
        &commitment[12..],
        expected_commitment.to_lower_hex_string(),
        "rendered commitment must be SHA256D(witness merkle root || witness reserved value)"
    );
    Ok(())
}

#[test]
fn template_orders_parent_then_child_with_dependency() -> Result<()> {
    let (state, _guard) = open_regtest()?;
    apply_genesis(&state)?;
    let _seed_tip_hash = seed_chain(&state, SEED_BLOCKS)?;

    let parent = seed_coinbase_spend();
    let parent_txid = parent.txid();
    let child = Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(parent_txid, 0),
            script_sig: p2sh_true_spend_script_sig(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(REGTEST_SUBSIDY_SATS - 2 * MEMPOOL_TX_FEE_SATS),
            script_pubkey: p2sh_true_output(),
        }],
        lock_time: LockTime::ZERO,
    };
    let child_txid = child.txid();

    admit_to_mempool(&state, &parent)?;
    admit_to_mempool(&state, &child)?;

    let handler = mining_handler(&state);
    let template = handler.dispatch("getblocktemplate", &json!([{"rules": ["segwit"]}]))?;
    let template_txs = template
        .get("transactions")
        .and_then(|entry| entry.as_array())
        .map_or(&[][..], |entries| entries.as_slice());
    assert_eq!(template_txs.len(), 2, "both txs must be selected");
    assert_eq!(
        template_txs[0]
            .get("txid")
            .and_then(|value| value.as_str())
            .ok_or_else(|| anyhow::anyhow!("first template tx missing txid"))?,
        parent_txid.to_string(),
        "parent must precede child in topological template order"
    );
    assert_eq!(
        template_txs[1]
            .get("txid")
            .and_then(|value| value.as_str())
            .ok_or_else(|| anyhow::anyhow!("second template tx missing txid"))?,
        child_txid.to_string(),
        "child must follow parent in topological template order"
    );

    let parent_depends = template_txs[0]
        .get("depends")
        .and_then(|value| value.as_array())
        .map_or(&[][..], |entries| entries.as_slice());
    assert!(
        parent_depends.is_empty(),
        "parent has no in-template dependencies"
    );

    let child_depends = template_txs[1]
        .get("depends")
        .and_then(|value| value.as_array())
        .map_or(&[][..], |entries| entries.as_slice());
    assert_eq!(
        child_depends.len(),
        1,
        "child depends on the one in-template parent"
    );
    assert_eq!(
        child_depends[0]
            .as_i64()
            .and_then(|n| u64::try_from(n).ok()),
        Some(1_u64),
        "child depends index must be the one-based parent position"
    );

    Ok(())
}

#[test]
fn invalidateblock_readmits_parent_before_child_in_dependency_order() -> Result<()> {
    let (state, _guard) = open_regtest()?;
    apply_genesis(&state)?;
    let seed_tip_hash = seed_chain(&state, SEED_BLOCKS)?;

    // Parent spends the matured height-1 coinbase; the child spends the
    // parent. Both pay MEMPOOL_TX_FEE_SATS.
    let parent = seed_coinbase_spend();
    let parent_txid = parent.txid();
    let child = Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(parent_txid, 0),
            script_sig: p2sh_true_spend_script_sig(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(REGTEST_SUBSIDY_SATS - 2 * MEMPOOL_TX_FEE_SATS),
            script_pubkey: p2sh_true_output(),
        }],
        lock_time: LockTime::ZERO,
    };
    let child_txid = child.txid();

    admit_to_mempool(&state, &parent)?;
    admit_to_mempool(&state, &child)?;
    let sequence_before_reorg = state.mempool().read().sequence_number();

    let block = mine_regtest_block(&state, seed_tip_hash, SEED_BLOCKS + 1, vec![parent, child])?;
    assert_eq!(
        state.mempool().read().len(),
        0,
        "connect must drain the confirmed pair"
    );
    let mined_hash = Hash256::from(block.block_hash());

    bitcoin_rs_node::reorg::invalidate_block(
        &state.chainstate(),
        &state.chain_followers(),
        mined_hash,
    )
    .map_err(|error| anyhow::anyhow!("invalidateblock failed: {error}"))?;

    let tip = current_tip(&state)?;
    assert_eq!(tip.height, SEED_BLOCKS, "the mined block must roll back");
    {
        let mempool = state.mempool();
        let pool = mempool.read();
        assert!(pool.contains_txid(&parent_txid), "the parent returns");
        assert!(
            pool.contains_txid(&child_txid),
            "the child follows its parent"
        );
        assert_eq!(pool.len(), 2, "the coinbase must stay out");
        assert_eq!(
            pool.sequence_number(),
            sequence_before_reorg + 4,
            "connect removes two, reconsideration admits parent then child"
        );
    }
    Ok(())
}

/// Records every published change as `(sequence, txid, outcome)`.
#[derive(Default)]
struct RecordingMempoolObserver {
    changes: Mutex<Vec<(u64, Hash256, MutationOutcome)>>,
}

impl MempoolObserver for RecordingMempoolObserver {
    fn wants_accepted_transactions(&self) -> bool {
        false
    }
    fn on_mutation(&self, envelope: &MutationEnvelope) {
        let result = &envelope.result;
        let mut changes = self.changes.lock();
        for (offset, change) in result.changes.iter().enumerate() {
            let sequence = result.sequence_of(offset).unwrap_or(u64::MAX);
            changes.push((sequence, change.txid, change.outcome));
        }
    }
}

/// Reorg re-admission publishes through the run-composed gateway:
/// two Accepted changes, parent before child, origin `Reorg`, contiguous
/// sequences. The apply path's raw sweep bypasses observers by design, so
/// these two changes are the only publications the gateway emits here.
#[test]
fn invalidateblock_readmission_publishes_events_through_composed_gateway() -> Result<()> {
    let (state, _guard) = open_regtest()?;
    apply_genesis(&state)?;
    let seed_tip_hash = seed_chain(&state, SEED_BLOCKS)?;

    // The node carries the gateway built for this pool, so publication runs
    // through the same path production uses.
    let observer = Arc::new(RecordingMempoolObserver::default());
    let gateway = state.mempool_gateway();
    assert!(Arc::ptr_eq(gateway.pool(), &state.mempool()));
    assert_eq!(gateway.engine(), state.config().validation.engine);
    gateway
        .attach_observer_leg("test-recorder", observer.clone())
        .unwrap_or_else(|error| panic!("the node installs an observer slot to extend: {error}"));
    let parent = seed_coinbase_spend();
    let parent_txid = parent.txid();
    let child = Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(parent_txid, 0),
            script_sig: p2sh_true_spend_script_sig(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(REGTEST_SUBSIDY_SATS - 2 * MEMPOOL_TX_FEE_SATS),
            script_pubkey: p2sh_true_output(),
        }],
        lock_time: LockTime::ZERO,
    };
    let child_txid = child.txid();

    let block = mine_regtest_block(&state, seed_tip_hash, SEED_BLOCKS + 1, vec![parent, child])?;
    let mined_hash = Hash256::from(block.block_hash());
    bitcoin_rs_node::reorg::invalidate_block(
        &state.chainstate(),
        &state.chain_followers(),
        mined_hash,
    )
    .map_err(|error| anyhow::anyhow!("invalidateblock failed: {error}"))?;

    let tip = current_tip(&state)?;
    assert_eq!(tip.height, SEED_BLOCKS, "the mined block must roll back");
    let changes = observer.changes.lock();
    assert_eq!(
        *changes,
        vec![
            (1, Hash256::from(parent_txid), MutationOutcome::Accepted,),
            (2, Hash256::from(child_txid), MutationOutcome::Accepted,),
        ],
        "parent before child, contiguous sequences"
    );
    Ok(())
}

#[test]
fn invalidateblock_readmits_a_below_floor_family_through_the_deferred_fence() -> Result<()> {
    let (state, _guard) = open_regtest()?;
    apply_genesis(&state)?;
    let seed_tip_hash = seed_chain(&state, SEED_BLOCKS)?;

    // The parent spends the matured seed coinbase but offers a 1-sat fee,
    // far below the 1 000 sat/kvB relay floor. Reorg re-admission bypasses
    // the floor, the way Core's `bypassLimits` skips `GetMinFee`: the family
    // already paid for its place when it was mined.
    let parent = seed_coinbase_spend_with_fee(1);
    let parent_txid = parent.txid();
    let child = Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(parent_txid, 0),
            script_sig: p2sh_true_spend_script_sig(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(REGTEST_SUBSIDY_SATS - 1 - 5_000),
            script_pubkey: p2sh_true_output(),
        }],
        lock_time: LockTime::ZERO,
    };
    let child_txid = child.txid();

    let block = mine_regtest_block(&state, seed_tip_hash, SEED_BLOCKS + 1, vec![parent, child])?;
    let mined_hash = Hash256::from(block.block_hash());
    bitcoin_rs_node::reorg::invalidate_block(
        &state.chainstate(),
        &state.chain_followers(),
        mined_hash,
    )
    .map_err(|error| anyhow::anyhow!("invalidateblock failed: {error}"))?;

    let tip = current_tip(&state)?;
    assert_eq!(tip.height, SEED_BLOCKS, "the mined block must roll back");
    let mempool = state.mempool();
    let pool = mempool.read();
    assert!(
        pool.contains_txid(&parent_txid),
        "the deferred fence must re-admit the below-floor parent"
    );
    assert!(
        pool.contains_txid(&child_txid),
        "the child must re-enter once its parent is back"
    );
    Ok(())
}

#[test]
fn submitblock_accepts_block_without_prior_mempool_admission() -> Result<()> {
    let (state, _guard) = open_regtest()?;
    apply_genesis(&state)?;
    let seed_tip_hash = seed_chain(&state, SEED_BLOCKS)?;

    // A consensus-valid spend that never passes through the mempool gateway.
    let tx = seed_coinbase_spend();
    assert!(!state.mempool().read().contains_txid(&tx.txid()));

    let block = assemble_regtest_block(seed_tip_hash, SEED_BLOCKS + 1, vec![tx])?;
    let block_hex = consensus_bytes(&block).to_lower_hex_string();

    let handler = mining_handler(&state);
    let verdict = handler.dispatch("submitblock", &json!([block_hex]))?;
    assert!(
        verdict.is_null(),
        "submitblock must accept a valid block, got: {verdict}"
    );

    let tip = current_tip(&state)?;
    assert_eq!(tip.height, SEED_BLOCKS + 1, "tip must advance by one");
    assert_eq!(
        tip.hash,
        Hash256::from(block.block_hash()),
        "tip hash must equal the submitted block hash"
    );
    Ok(())
}

#[test]
fn submitblock_rejects_stale_template_with_inconclusive_prevblk() -> Result<()> {
    let (state, _guard) = open_regtest()?;
    apply_genesis(&state)?;
    let old_tip = seed_chain(&state, SEED_BLOCKS)?;

    let tx = seed_coinbase_spend();
    admit_to_mempool(&state, &tx)?;

    let handler = mining_handler(&state);
    let template = handler.dispatch("getblocktemplate", &json!([{"rules": ["segwit"]}]))?;
    let template_txs = template
        .get("transactions")
        .and_then(|value| value.as_array())
        .map_or(&[][..], |entries| entries.as_slice());
    let accepted = assemble_from_template(&template, template_txs)?;
    let accepted_hex = consensus_bytes(&accepted).to_lower_hex_string();
    let verdict = handler.dispatch("submitblock", &json!([accepted_hex]))?;
    assert!(
        verdict.is_null(),
        "first block must be accepted, got: {verdict}"
    );

    // A competing block built on the superseded template still points at old_tip.
    let stale_block = assemble_regtest_block(old_tip, SEED_BLOCKS + 1, Vec::new())?;
    let stale_hex = consensus_bytes(&stale_block).to_lower_hex_string();
    let reject = handler.dispatch("submitblock", &json!([stale_hex]))?;
    let reason = reject
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("submitblock"))?;
    assert!(
        reason.contains("inconclusive-not-best-prevblk"),
        "stale template must be rejected with PrevHashMismatch: {reason}"
    );

    Ok(())
}

#[test]
fn post_connect_template_pool_and_estimator_observables() -> Result<()> {
    let (state, _guard) = open_regtest()?;
    apply_genesis(&state)?;
    let _seed_tip_hash = seed_chain(&state, SEED_BLOCKS)?;

    let handler = mining_handler(&state);
    let before = handler.dispatch("estimatesmartfee", &json!([1, "conservative"]))?;
    assert!(
        before.get("feerate").is_none(),
        "empty estimator omits feerate"
    );
    let before_errors = before
        .get("errors")
        .and_then(|value| value.as_array())
        .map_or(&[][..], |entries| entries.as_slice());
    assert!(
        before_errors.iter().any(|value| {
            value
                .as_str()
                .is_some_and(|text| text.contains("Insufficient data"))
        }),
        "empty estimator reports insufficient data: {before}"
    );

    let parent = seed_coinbase_spend();
    let parent_txid = parent.txid();
    let child = Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(parent_txid, 0),
            script_sig: p2sh_true_spend_script_sig(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(REGTEST_SUBSIDY_SATS - 2 * MEMPOOL_TX_FEE_SATS),
            script_pubkey: p2sh_true_output(),
        }],
        lock_time: LockTime::ZERO,
    };
    admit_to_mempool(&state, &parent)?;
    admit_to_mempool(&state, &child)?;

    let template = handler.dispatch("getblocktemplate", &json!([{"rules": ["segwit"]}]))?;
    let template_txs = template
        .get("transactions")
        .and_then(|value| value.as_array())
        .map_or(&[][..], |entries| entries.as_slice());
    let block = assemble_from_template(&template, template_txs)?;
    let block_hex = consensus_bytes(&block).to_lower_hex_string();
    let verdict = handler.dispatch("submitblock", &json!([block_hex]))?;
    assert!(
        verdict.is_null(),
        "submitblock must accept the block: {verdict}"
    );

    let next = handler.dispatch("getblocktemplate", &json!([{"rules": ["segwit"]}]))?;
    let next_txs = next
        .get("transactions")
        .and_then(|value| value.as_array())
        .map_or(&[][..], |entries| entries.as_slice());
    assert!(
        next_txs.is_empty(),
        "next template must have no transactions after connect"
    );
    assert_eq!(
        required_str(&next, "previousblockhash")?,
        block.block_hash().to_string(),
        "next template must build on the accepted block"
    );

    let mempool_info = handler.dispatch("getmempoolinfo", &json!([]))?;
    assert_eq!(
        required_u64(&mempool_info, "size")?,
        0,
        "mempool must be empty after block connect"
    );

    let raw_mempool = handler.dispatch("getrawmempool", &json!([]))?;
    let raw_mempool_array = raw_mempool
        .as_array()
        .map_or(&[][..], |entries| entries.as_slice());
    assert!(
        raw_mempool_array.is_empty(),
        "getrawmempool must return no txids"
    );

    let after = handler.dispatch("estimatesmartfee", &json!([1, "conservative"]))?;
    assert!(
        after.get("errors").is_none(),
        "estimate with data has no errors: {after}"
    );
    let feerate = after
        .get("feerate")
        .and_then(sonic_rs::JsonValueTrait::as_f64)
        .ok_or_else(|| anyhow::anyhow!("estimatesmartfee must report feerate"))?;
    assert!(feerate > 0.0, "confirmed fee rate must be positive");
    assert_eq!(
        required_u64(&after, "blocks")?,
        1_u64,
        "one-block conf target estimates within one block"
    );

    Ok(())
}

/// The miner's view through the real RPC dispatcher: `prioritisetransaction`
/// reorders the next `getblocktemplate`, leaves the fees the coinbase claims
/// alone, and moves only the fee-priority component of `longpollid`. Undoing
/// the delta restores the order under a third, distinct generation.
#[test]
fn prioritisetransaction_reorders_the_rpc_template_and_moves_only_the_fee_component() -> Result<()>
{
    let fx = priority_fixture()?;
    let before = fx.template()?;
    assert_eq!(before.txids, txid_strings(&[&fx.high, &fx.low]));

    fx.prioritise(&fx.low, PRIORITY_DELTA_SATS)?;
    let raised = fx.template()?;
    assert_eq!(
        raised.txids,
        txid_strings(&[&fx.low, &fx.high]),
        "the prioritised transaction must lead the next template"
    );
    assert_eq!(
        raised.fees.iter().rev().copied().collect::<Vec<_>>(),
        before.fees,
        "prioritisation reorders; it never changes the fee a transaction pays"
    );
    assert_eq!(raised.coinbase_value, before.coinbase_value);
    let (before_id, raised_id) = (before.id()?, raised.id()?);
    assert_eq!(raised_id.tip, before_id.tip);
    assert_eq!(raised_id.mempool_sequence, before_id.mempool_sequence);
    assert_ne!(raised_id.fee_delta_sequence, before_id.fee_delta_sequence);
    assert_eq!(raised.long_poll_id, live_long_poll_id(&fx.state)?);

    fx.prioritise(&fx.low, -PRIORITY_DELTA_SATS)?;
    let restored = fx.template()?;
    assert_eq!(
        restored.txids, before.txids,
        "removing the delta restores the order"
    );
    assert_ne!(
        restored.long_poll_id, raised.long_poll_id,
        "the fee component only moves forward; a generation never repeats"
    );
    assert_ne!(restored.long_poll_id, before.long_poll_id);
    Ok(())
}

/// A miner that still sends the legacy `longpollid` shape without a fee
/// component is answered through the real RPC dispatcher: the id parses as
/// fee revision zero.
#[test]
fn getblocktemplate_accepts_the_legacy_longpollid_shape_as_fee_zero() -> Result<()> {
    let fx = priority_fixture()?;
    let current = fx.template()?;
    // No prioritisation has run, so the live fee revision is zero and the
    // live id already carries no suffix: it is the legacy shape.
    assert!(
        !current.long_poll_id.contains(':'),
        "precondition: the live id {:?} carries no fee suffix",
        current.long_poll_id
    );
    // A prioritisation moves only the fee component, so the previous legacy
    // id is stale and must resolve at once instead of failing as malformed.
    fx.prioritise(&fx.low, PRIORITY_DELTA_SATS)?;
    let legacy = current.long_poll_id;
    // A legacy id resolves against the fee-zero generation without waiting;
    // the bound fails the test instead of hanging it if that regresses.
    let answered = fx.poll(&legacy).collect(PROMPT)??;
    assert_ne!(
        answered.long_poll_id, legacy,
        "a legacy id must resolve against the fee-zero generation, not fail as malformed"
    );
    assert_eq!(
        answered.txids,
        txid_strings(&[&fx.low, &fx.high]),
        "the stale legacy id must be answered with the reordered template"
    );
    Ok(())
}
