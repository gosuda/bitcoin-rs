//! Window pre-proof consults the node-owned script-execution cache.

use std::sync::Arc;

use bitcoin_rs_chain::NodeStatus;
use bitcoin_rs_chain::regtest_fixture::{
    coinbase, mined_block_with_prev_hash, mined_regtest_child_at as mined_child,
};
use bitcoin_rs_consensus::{ScriptExecutionCache, UtxoView, ValidationEngine};
use bitcoin_rs_primitives::{
    Amount, BlockHash, BlockPayload, Hash256, LockTime, Network, OutPoint, Sequence, Tx, TxIn,
    TxOut, Witness,
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
/// Applies regtest children `1..=101` atop genesis, returning the first two
/// coinbases both cache tests mature their spends from, plus the tip hash.
/// Only the funding transactions are retained; every applied block is
/// dropped after its own commit.
fn matured_funding(
    handles: &Chainstate,
) -> Result<(Tx, Tx, BlockHash), Box<dyn std::error::Error>> {
    let network = Network::Regtest;
    let mut parent = network.genesis_block().block_hash();
    let mut funded: Option<Tx> = None;
    let mut funded_next: Option<Tx> = None;
    for height in 1..=101 {
        let block = mined_child(parent, height).map_err(|error| error.to_string())?;
        handles
            .apply_block(&BlockPayload::from_local(block.clone()))
            .map_err(|error| error.to_string())?;
        if height == 1 {
            funded = Some(block.txs[0].clone());
        }
        if height == 2 {
            funded_next = Some(block.txs[0].clone());
        }
        parent = block.block_hash();
    }
    Ok((
        funded.ok_or("height-1 coinbase missing")?,
        funded_next.ok_or("height-2 coinbase missing")?,
        parent,
    ))
}

/// A spend of `funded`'s first output to an `OP_TRUE` output, differing only
/// in its unlocking script: both cache tests build their spends from it.
fn spend_tx(funded: &Tx, script_sig: Vec<u8>) -> Tx {
    Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(funded.txid(), 0),
            script_sig: script_sig.into(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(funded.outputs[0].value.to_sat() - 1_000),
            script_pubkey: vec![0x51].into(),
        }],
    }
}

/// Window commit consumes a verified script-cache entry exactly once.
#[test]
fn window_commit_consumes_verified_script_cache_entry() -> Result<(), Box<dyn std::error::Error>> {
    let network = Network::Regtest;
    let mut handles: Chainstate = handles(network, Arc::new(UtxoSet::new()));
    seed_genesis(&handles).map_err(|error| error.to_string())?;

    // Mature fixture coinbases for the spend below; this test spends only
    // the first.
    let (funded, _, parent) = matured_funding(&handles)?;

    // Install the node-owned cache after the prefix applies, so the only
    // take in this test is the window pre-proof's.
    let cache = Arc::new(ScriptExecutionCache::new());
    handles.script_cache = Some(Arc::clone(&cache));

    // `OP_TRUE` against the fixture coinbase's empty script leaves a truthy
    // top element: a genuinely valid spend under every flag set.
    let prevout = OutPoint::new(funded.txid(), 0);
    let good = spend_tx(&funded, vec![0x51]);
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

    let payload = BlockPayload::from_local(block);
    let outcomes = handles
        .apply_window(&[payload])
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

/// A window that fails its proof after taking entries restores them, so the
/// retry reuses the positives instead of re-verifying scripts.
#[test]
fn a_failed_window_restores_the_script_cache_entries_it_took()
-> Result<(), Box<dyn std::error::Error>> {
    let network = Network::Regtest;
    let mut handles: Chainstate = handles(network, Arc::new(UtxoSet::new()));
    seed_genesis(&handles).map_err(|error| error.to_string())?;

    // Mature two fixture coinbases: the first funds the valid spend, the
    // second funds the invalid one.
    let (funded, funded_next, parent) = matured_funding(&handles)?;

    let cache = Arc::new(ScriptExecutionCache::new());
    handles.script_cache = Some(Arc::clone(&cache));

    // `OP_TRUE` is a genuinely valid spend; `OP_0` leaves a falsy top
    // element, so its scripts fail while every non-script check still passes.
    let good = spend_tx(&funded, vec![0x51]);
    let bad = spend_tx(&funded_next, vec![0x00]);
    let good_wtxid = good.wtxid();

    let first = mined_block_with_prev_hash(parent, 102, vec![coinbase(102), good])
        .map_err(|error| error.to_string())?;
    let second = mined_block_with_prev_hash(first.block_hash(), 103, vec![coinbase(103), bad])
        .map_err(|error| error.to_string())?;
    for block in [&first, &second] {
        handles
            .block_tree
            .write()
            .insert_header(block.header, NodeStatus::HeaderValid)
            .map_err(|error| error.to_string())?;
    }

    let applied = handles
        .applied_tip
        .load_full()
        .ok_or("window test needs an applied tip")?;
    let softfork = {
        let tree = handles.block_tree.read();
        bitcoin_rs_chain::softfork_state(&tree, network, Some(applied.tip_id), 102)
    };
    let flags = bitcoin_rs_consensus::verify_block::verify_flags(
        network,
        102,
        Hash256::from(first.block_hash()),
        softfork,
    );
    let prevouts = [(OutPoint::new(funded.txid(), 0), funded.outputs[0].clone())];
    bitcoin_rs_consensus::verify_tx::verify_transaction(
        &first.txs[1],
        &PrevoutMap(&prevouts),
        102,
        0,
        flags,
        ValidationEngine::Native,
        None,
    )
    .map_err(|error| error.to_string())?;
    cache.insert(good_wtxid, flags);

    let payloads = [
        BlockPayload::from_local(first.clone()),
        BlockPayload::from_local(second),
    ];
    // Rollback witness: bad script at 103 fails the pre-proof after the checks took the entry.
    let proven = super::prove_window(&handles, &payloads).proven;
    assert!(
        proven.is_empty(),
        "bad script at 103 must fail the pre-proof"
    );
    assert!(
        cache.take(good_wtxid, flags),
        "failed pre-proof must restore taken entries"
    );

    // Prefix commit: the valid prefix commits and reports how far it got.
    cache.insert(good_wtxid, flags);
    let err = handles
        .apply_window(&payloads)
        .err()
        .ok_or("the invalid second block must fail the window apply")?;
    assert_eq!(err.applied, 1, "one block committed before the failure");
    assert_eq!(err.committed.len(), 1);
    assert_eq!(err.committed[0].tip.height, 102);
    assert_eq!(err.committed[0].hash, Hash256::from(first.block_hash()));
    assert!(
        matches!(
            err.source,
            crate::ApplyError::Consensus(bitcoin_rs_consensus::ConsensusError::Script { .. })
        ),
        "failure must be the second block's script verdict"
    );
    let tip = handles
        .applied_tip
        .load_full()
        .ok_or("window test needs an applied tip")?;
    assert_eq!(tip.height, 102, "the valid prefix stays committed");
    assert!(
        !cache.take(good_wtxid, flags),
        "fallback commit consumed the restored entry"
    );
    Ok(())
}
/// A window whose pre-proof succeeds but whose second block fails admission
/// restores only the uncommitted block's takes: the committed prefix stays
/// consumed while the refused block's positives stay reusable.
#[test]
#[expect(clippy::too_many_lines)]
fn a_window_refused_after_proof_restores_only_uncommitted_takes()
-> Result<(), Box<dyn std::error::Error>> {
    let network = Network::Regtest;
    let mut handles: Chainstate = handles(network, Arc::new(UtxoSet::new()));
    seed_genesis(&handles).map_err(|error| error.to_string())?;

    let (funded, funded_next, parent) = matured_funding(&handles)?;

    let cache = Arc::new(ScriptExecutionCache::new());
    handles.script_cache = Some(Arc::clone(&cache));

    let first_spend = spend_tx(&funded, vec![0x51]);
    let second_spend = spend_tx(&funded_next, vec![0x51]);
    let first_wtxid = first_spend.wtxid();
    let second_wtxid = second_spend.wtxid();

    let first = mined_block_with_prev_hash(parent, 102, vec![coinbase(102), first_spend])
        .map_err(|error| error.to_string())?;
    let mut rich_coinbase = coinbase(103);
    rich_coinbase.outputs[0].value =
        Amount::from_sat(rich_coinbase.outputs[0].value.to_sat() + 1_000_000);
    let second =
        mined_block_with_prev_hash(first.block_hash(), 103, vec![rich_coinbase, second_spend])
            .map_err(|error| error.to_string())?;
    for block in [&first, &second] {
        handles
            .block_tree
            .write()
            .insert_header(block.header, NodeStatus::HeaderValid)
            .map_err(|error| error.to_string())?;
    }

    let first_hash = Hash256::from(first.block_hash());
    let second_hash = Hash256::from(second.block_hash());
    let (flags_first, flags_second) = {
        let applied = handles
            .applied_tip
            .load_full()
            .ok_or("window test needs an applied tip")?;
        let tree = handles.block_tree.read();
        let softfork_first =
            bitcoin_rs_chain::softfork_state(&tree, network, Some(applied.tip_id), 102);
        let flags_first = bitcoin_rs_consensus::verify_block::verify_flags(
            network,
            102,
            first_hash,
            softfork_first,
        );
        let first_id = tree
            .lookup(first_hash)
            .ok_or("first header must be in the tree")?;
        let softfork_second = bitcoin_rs_chain::softfork_state(&tree, network, Some(first_id), 103);
        let flags_second = bitcoin_rs_consensus::verify_block::verify_flags(
            network,
            103,
            second_hash,
            softfork_second,
        );
        (flags_first, flags_second)
    };
    let first_prevouts = [(OutPoint::new(funded.txid(), 0), funded.outputs[0].clone())];
    bitcoin_rs_consensus::verify_tx::verify_transaction(
        &first.txs[1],
        &PrevoutMap(&first_prevouts),
        102,
        0,
        flags_first,
        ValidationEngine::Native,
        None,
    )
    .map_err(|error| error.to_string())?;
    cache.insert(first_wtxid, flags_first);
    let second_prevouts = [(
        OutPoint::new(funded_next.txid(), 0),
        funded_next.outputs[0].clone(),
    )];
    bitcoin_rs_consensus::verify_tx::verify_transaction(
        &second.txs[1],
        &PrevoutMap(&second_prevouts),
        103,
        0,
        flags_second,
        ValidationEngine::Native,
        None,
    )
    .map_err(|error| error.to_string())?;
    cache.insert(second_wtxid, flags_second);

    let payloads = [
        BlockPayload::from_local(first),
        BlockPayload::from_local(second),
    ];
    let err = handles
        .apply_window(&payloads)
        .err()
        .ok_or("the inflated coinbase must fail the window apply")?;
    assert_eq!(err.applied, 1, "one block committed before the failure");
    assert_eq!(err.committed.len(), 1);
    assert_eq!(err.committed[0].tip.height, 102);
    assert_eq!(err.committed[0].hash, first_hash);
    assert!(
        matches!(
            err.source,
            crate::ApplyError::Consensus(
                bitcoin_rs_consensus::ConsensusError::CoinbaseAmount { .. }
            )
        ),
        "failure must be the second block's coinbase amount"
    );
    assert!(
        !cache.take(first_wtxid, flags_first),
        "committed prefix stays consumed"
    );
    assert!(
        cache.take(second_wtxid, flags_second),
        "refused block restores the takes it never committed"
    );
    Ok(())
}
