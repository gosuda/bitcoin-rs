//! Window pre-proof consults the node-owned script-execution cache.

use std::sync::Arc;

use bitcoin_rs_chain::NodeStatus;
use bitcoin_rs_chain::regtest_fixture::{
    coinbase, mined_block_with_prev_hash, mined_regtest_child_at as mined_child,
};
use bitcoin_rs_consensus::{ScriptExecutionCache, UtxoView, ValidationEngine};
use bitcoin_rs_primitives::{
    Amount, Hash256, LockTime, Network, OutPoint, Sequence, Tx, TxIn, TxOut, Witness,
    consensus_bytes,
};
use bitcoin_rs_utxo::UtxoSet;

use crate::Chainstate;
use crate::test_fixtures::{handles, seed_genesis};

/// Prevout lookup over a fixed slice for native single-transaction
/// verification.
struct PrevoutMap<'a>(&'a [(OutPoint, TxOut)]);

impl UtxoView for PrevoutMap<'_> {
    fn lookup(&self, outpoint: &OutPoint) -> Option<TxOut> {
        self.0
            .iter()
            .find(|(candidate, _)| candidate == outpoint)
            .map(|(_, txout)| txout.clone())
    }
}

/// Window commit consumes a verified script-cache entry exactly once.
#[test]
fn window_commit_consumes_verified_script_cache_entry() -> Result<(), Box<dyn std::error::Error>> {
    let network = Network::Regtest;
    let mut handles: Chainstate = handles(network, Arc::new(UtxoSet::new()));
    seed_genesis(&handles).map_err(|error| error.to_string())?;

    // Mature one fixture coinbase for the spend below.
    let mut parent = network.genesis_block().block_hash();
    let mut funded: Option<Tx> = None;
    for height in 1..=101 {
        let block = mined_child(parent, height).map_err(|error| error.to_string())?;
        handles
            .apply_block(&block, None)
            .map_err(|error| error.to_string())?;
        if height == 1 {
            funded = Some(block.txs[0].clone());
        }
        parent = block.block_hash();
    }
    let funded = funded.ok_or("height-1 coinbase missing")?;

    // Install the node-owned cache after the prefix applies, so the only
    // take in this test is the window pre-proof's.
    let cache = Arc::new(ScriptExecutionCache::new());
    handles.script_cache = Some(Arc::clone(&cache));

    // `OP_TRUE` against the fixture coinbase's empty script leaves a truthy
    // top element: a genuinely valid spend under every flag set.
    let prevout = OutPoint::new(funded.txid(), 0);
    let input_value = funded.outputs[0].value.to_sat();
    let good = Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: prevout,
            script_sig: vec![0x51].into(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(input_value - 1_000),
            script_pubkey: vec![0x51].into(),
        }],
    };
    let wtxid = good.wtxid();
    let block = mined_block_with_prev_hash(parent, 102, vec![coinbase(102), good])
        .map_err(|error| error.to_string())?;
    handles
        .block_tree
        .write()
        .insert_header(block.header, NodeStatus::HeaderValid)
        .map_err(|error| error.to_string())?;

    // Seed exactly the flags the commit path derives: same softfork state,
    // height, and block hash as `connect.rs` uses for this block.
    let block_hash = Hash256::from(block.block_hash());
    let applied = handles
        .applied_tip
        .load_full()
        .ok_or("window test needs an applied tip")?;
    let next_height = applied.height + 1;
    let softfork = {
        let tree = handles.block_tree.read();
        bitcoin_rs_chain::softfork_state(&tree, network, Some(applied.tip_id), next_height)
    };
    let flags = bitcoin_rs_consensus::verify_block::verify_flags(
        network,
        next_height,
        block_hash,
        softfork,
    );
    // Seed only what real native verification accepts, mirroring the
    // gateway's second pass: finality here is cutoff-independent (zero
    // locktime with max sequence), so the cutoff plays no role in this
    // verdict.
    let prevouts = [(prevout, funded.outputs[0].clone())];
    bitcoin_rs_consensus::verify_tx::verify_transaction(
        &block.txs[1],
        &PrevoutMap(&prevouts),
        next_height,
        0,
        flags,
        ValidationEngine::Native,
        None,
    )
    .map_err(|error| error.to_string())?;
    cache.insert(wtxid, flags);

    let outcomes = handles
        .apply_window(&[&block], &[bytes::Bytes::from(consensus_bytes(&block))])
        .map_err(|error| error.to_string())?;
    assert_eq!(outcomes.len(), 1, "window must commit its one block");
    assert_eq!(outcomes[0].tip.height, next_height);
    assert_eq!(outcomes[0].hash, block_hash);
    assert!(
        !cache.take(wtxid, flags),
        "the window take must have consumed the entry exactly once"
    );
    Ok(())
}
