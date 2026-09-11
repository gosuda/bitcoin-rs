use std::sync::Arc;
use std::sync::atomic::Ordering;

use bitcoin_rs_mempool::MempoolObserver;
use bitcoin_rs_mempool::MutationEnvelope;
use bitcoin_rs_primitives::BlockHash;
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_primitives::Network;
use bitcoin_rs_primitives::OutPoint;
use bitcoin_rs_primitives::Tx;
use bitcoin_rs_primitives::TxIn;
use bitcoin_rs_primitives::TxOut;
use bitcoin_rs_primitives::Txid;
use bitcoin_rs_utxo::UtxoSet;
use parking_lot::Mutex;

use super::Chainstate;
use super::applied_header_tip;
use super::consensus_rule_tests::apply_handles_without_tx_index;
use super::consensus_rule_tests::coinbase_transaction;
use super::consensus_rule_tests::mined_block_with_prev_hash_and_transactions;

/// An observer that captures the gateway's `stable_generation` when a
/// mutation fires. We pass the gateway in via an Arc.
struct GatewayGenerationRecorder {
    /// Bound after the gateway exists: the gateway owns the observer, so
    /// the observer cannot own the gateway at construction. An unbound
    /// recorder records `None`, which fails the caller's assertion rather
    /// than passing quietly.
    gateway: std::sync::OnceLock<Arc<bitcoin_rs_mempool::MempoolGateway>>,
    seen: Mutex<Vec<Option<u64>>>,
}

impl GatewayGenerationRecorder {
    fn bind(&self, gateway: &Arc<bitcoin_rs_mempool::MempoolGateway>) {
        let _ = self.gateway.set(Arc::clone(gateway));
    }
}

impl MempoolObserver for GatewayGenerationRecorder {
    fn on_mutation(&self, _envelope: &MutationEnvelope) {
        let generation = self
            .gateway
            .get()
            .and_then(|gateway| gateway.stable_generation());
        self.seen.lock().push(generation);
    }
}

fn setup_regtest_with_genesis() -> (Chainstate, bitcoin_rs_primitives::Block, BlockHash) {
    let genesis = Network::Regtest.genesis_block();
    let genesis_hash = genesis.block_hash();
    let handles = apply_handles_without_tx_index(Network::Regtest, Arc::new(UtxoSet::new()));
    let genesis_tip = applied_header_tip(&handles, genesis_hash.into(), &genesis, 0)
        .unwrap_or_else(|error| panic!("genesis tip must apply: {error}"));
    handles.applied_tip.store(Some(Arc::new(genesis_tip)));
    (handles, genesis, genesis_hash)
}

/// `ARCH-07`: snapshot copies published cells without reserving generation.
#[test]
fn snapshot_reads_applied_tip_without_taking_a_transition() {
    let (handles, _genesis, genesis_hash) = setup_regtest_with_genesis();
    let snapshot = handles.snapshot();
    assert_eq!(
        snapshot.applied.as_ref().map(|tip| tip.hash),
        Some(Hash256::from(genesis_hash)),
        "snapshot copies the published applied tip"
    );
    assert_eq!(
        snapshot.applied.as_ref().map(|tip| tip.height),
        Some(0),
        "genesis is height zero"
    );
    assert_eq!(
        snapshot.chain_tx_count,
        handles.chain_tx_count.load(Ordering::Relaxed),
        "snapshot copies the applied tip with its published chain-tx count"
    );
    assert_eq!(
        handles.mempool_gateway.stable_generation(),
        Some(0),
        "reading a snapshot must not reserve mempool generation"
    );
}

/// `ARCH-07`: mutation is admitted only through `Chainstate` / `ChainTransition`.
#[test]
fn chain_transition_connect_and_finish_publish_the_new_tip() {
    let (handles, genesis, genesis_hash) = setup_regtest_with_genesis();
    let block = mined_block_with_prev_hash_and_transactions(
        genesis.block_hash(),
        vec![coinbase_transaction(1)],
    )
    .unwrap_or_else(|error| panic!("mine block: {error}"));
    let block_hash = Hash256::from(block.block_hash());

    let transition = handles
        .begin_transition()
        .unwrap_or_else(|error| panic!("begin transition: {error}"));
    let tip = transition
        .connect(&block)
        .unwrap_or_else(|error| panic!("connect through transition: {error}"));
    assert_eq!(tip.hash, block_hash);
    assert_eq!(tip.height, 1);
    transition
        .finish()
        .unwrap_or_else(|error| panic!("finish transition: {error}"));

    let snapshot = handles.snapshot();
    assert_eq!(
        snapshot.applied.as_ref().map(|tip| (tip.height, tip.hash)),
        Some((1, block_hash)),
        "committed connect is visible on the next snapshot"
    );
    assert_eq!(
        snapshot.chain_tx_count,
        handles.chain_tx_count.load(Ordering::Relaxed),
        "snapshot applied tip and chain-tx count are one publication"
    );
    assert_ne!(
        snapshot.applied.as_ref().map(|tip| tip.hash),
        Some(Hash256::from(genesis_hash))
    );
    assert_eq!(
        handles.mempool_gateway.stable_generation(),
        Some(2),
        "successful finish restores an even generation"
    );
}

#[test]
fn stable_generation_is_even_before_and_after_connect() {
    let (handles, genesis, _genesis_hash) = setup_regtest_with_genesis();
    assert_eq!(
        handles.mempool_gateway.stable_generation(),
        Some(0),
        "generation is even zero before any chain change"
    );

    let block = mined_block_with_prev_hash_and_transactions(
        genesis.block_hash(),
        vec![coinbase_transaction(1)],
    )
    .unwrap_or_else(|error| panic!("mine block: {error}"));

    handles
        .apply_block(&block)
        .unwrap_or_else(|error| panic!("connect succeeds: {error}"));

    assert_eq!(
        handles.mempool_gateway.stable_generation(),
        Some(2),
        "generation is even after a successful connect"
    );
}

#[test]
fn stable_generation_is_even_after_disconnect() {
    let (handles, genesis, _genesis_hash) = setup_regtest_with_genesis();

    let block = mined_block_with_prev_hash_and_transactions(
        genesis.block_hash(),
        vec![coinbase_transaction(1)],
    )
    .unwrap_or_else(|error| panic!("mine block: {error}"));

    handles
        .apply_block(&block)
        .unwrap_or_else(|error| panic!("connect: {error}"));
    assert_eq!(
        handles.mempool_gateway.stable_generation(),
        Some(2),
        "even after connect"
    );

    handles
        .disconnect_block(&block)
        .unwrap_or_else(|error| panic!("disconnect succeeds: {error}"));
    assert_eq!(
        handles.mempool_gateway.stable_generation(),
        Some(4),
        "generation is even after a successful disconnect"
    );
}

#[test]
fn stable_generation_is_even_after_window() {
    let (handles, genesis, _genesis_hash) = setup_regtest_with_genesis();

    let block1 = mined_block_with_prev_hash_and_transactions(
        genesis.block_hash(),
        vec![coinbase_transaction(1)],
    )
    .unwrap_or_else(|error| panic!("mine block 1: {error}"));

    let block2 = mined_block_with_prev_hash_and_transactions(
        block1.block_hash(),
        vec![coinbase_transaction(2)],
    )
    .unwrap_or_else(|error| panic!("mine block 2: {error}"));

    let blocks = [block1, block2];
    let serialized: Vec<bytes::Bytes> = blocks
        .iter()
        .map(|b| bytes::Bytes::from(super::consensus_bytes(b)))
        .collect();
    let block_refs: Vec<&bitcoin_rs_primitives::Block> = blocks.iter().collect();

    handles
        .apply_window(&block_refs, &serialized)
        .map_or_else(|error| panic!("window succeeds: {error}"), |_| ());

    assert_eq!(
        handles.mempool_gateway.stable_generation(),
        Some(2),
        "generation is even after a multi-block window"
    );
}

#[test]
fn chain_change_proof_finish_restores_even_generation() {
    let (handles, _genesis, _genesis_hash) = setup_regtest_with_genesis();

    let transition = handles
        .lock_transition()
        .unwrap_or_else(|error| panic!("transition: {error}"));
    let guard = handles
        .mempool_gateway
        .begin_chain_change()
        .unwrap_or_else(|error| panic!("begin chain change: {error}"));
    let proof = super::ChainChangeProof::new(transition, guard);

    assert_eq!(proof.odd_generation(), 1);
    assert_eq!(proof.reserved_even(), 2);
    assert_eq!(
        handles.mempool_gateway.stable_generation(),
        None,
        "odd while proof is held"
    );

    proof
        .finish()
        .unwrap_or_else(|error| panic!("finish restores even: {error}"));
    assert_eq!(
        handles.mempool_gateway.stable_generation(),
        Some(2),
        "even after finish"
    );
}

#[test]
fn observer_sees_none_during_connect() {
    let (mut handles, genesis, _genesis_hash) = setup_regtest_with_genesis();
    let recorder = Arc::new(GatewayGenerationRecorder {
        gateway: std::sync::OnceLock::new(),
        seen: Mutex::new(Vec::new()),
    });
    let observer: Arc<dyn MempoolObserver> = recorder.clone();
    let pool = handles.mempool_gateway.pool().clone();
    let gateway = Arc::new(bitcoin_rs_mempool::MempoolGateway::new(
        pool,
        Some(observer),
    ));
    recorder.bind(&gateway);
    handles.mempool_gateway = gateway;

    let block = mined_block_with_prev_hash_and_transactions(
        genesis.block_hash(),
        vec![coinbase_transaction(1)],
    )
    .unwrap_or_else(|error| panic!("mine block: {error}"));

    handles
        .apply_block(&block)
        .unwrap_or_else(|error| panic!("connect: {error}"));

    let seen = recorder.seen.lock();
    // The observer fires during remove_for_block, which happens while the
    // generation is odd. Every observed mutation must see None.
    assert!(
        seen.iter().all(|&g| g.is_none()),
        "all observer mutations during connect must see None (odd generation), got {:?}",
        *seen
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn invalidate_block_reconsiders_under_held_transition() {
    use bitcoin_rs_primitives::TxIn;
    use bitcoin_rs_primitives::consensus_bytes;
    use bitcoin_rs_primitives::{Amount, LockTime, Script, Sequence, TxOut, Witness};
    use bitcoin_rs_script::push_int;

    use super::consensus_rule_tests::MapBodyStore;

    let utxo = Arc::new(UtxoSet::new());
    let mut handles = apply_handles_without_tx_index(Network::Regtest, Arc::clone(&utxo));
    let bodies = Arc::new(MapBodyStore::default());
    handles.block_body_store = Some(bodies.clone());

    let genesis = Network::Regtest.genesis_block();
    let genesis_hash = genesis.block_hash();
    let genesis_tip = applied_header_tip(&handles, genesis_hash.into(), &genesis, 0)
        .unwrap_or_else(|error| panic!("genesis tip: {error}"));
    handles.applied_tip.store(Some(Arc::new(genesis_tip)));

    // Build a 101-block chain: block 1's coinbase carries the full
    // subsidy, and the tip block spends it after 100 confirmations
    // (coinbase maturity). The spend is the transaction that
    // reconsideration must readmit when the tip is invalidated.
    let subsidy = 5_000_000_000_u64;
    let mut prev_hash = genesis.block_hash();
    let mut first_txid = None;
    let mut spend_txid = None;
    let mut tip_hash: bitcoin_rs_primitives::Hash256 = genesis_hash.into();
    for height in 1..=101_u32 {
        let mut coinbase = coinbase_transaction(u8::try_from(height).unwrap_or(0xFF));
        if height == 1 {
            coinbase.outputs[0].value = Amount::from_sat(subsidy);
        }
        let mut txs = vec![coinbase];
        if height == 101 {
            let Some(first) = first_txid else {
                panic!("block 1 txid must exist")
            };
            txs.push(Tx {
                version: 2,
                inputs: vec![TxIn {
                    previous_output: OutPoint::new(first, 0),
                    script_sig: Script::from_bytes(push_int(1)),
                    sequence: Sequence::from_consensus(0xffff_ffff),
                    witness: Witness::new(),
                }],
                outputs: vec![TxOut {
                    value: Amount::from_sat(subsidy - 100_000),
                    script_pubkey: Script::new(),
                }],
                lock_time: LockTime::from_consensus(0),
            });
        }
        let block = mined_block_with_prev_hash_and_transactions(prev_hash, txs)
            .unwrap_or_else(|error| panic!("mine block {height}: {error}"));
        if height == 1 {
            first_txid = Some(block.txs[0].txid());
        }
        if height == 101 {
            spend_txid = Some(block.txs[1].txid());
        }
        let raw = bytes::Bytes::from(consensus_bytes(&block));
        let tip = handles
            .apply_block_with_serialized(&block, raw.clone())
            .unwrap_or_else(|error| panic!("apply block {height}: {error}"))
            .tip;
        bodies
            .bodies
            .write()
            .insert((tip.height, tip.hash), raw.to_vec());
        prev_hash = block.block_hash();
        tip_hash = tip.hash;
    }
    let Some(spend_txid) = spend_txid else {
        panic!("block 101 must have a spend tx")
    };

    // Install the generation recorder before invalidation so it captures
    // every mempool mutation during reconsideration.
    let recorder = Arc::new(GatewayGenerationRecorder {
        gateway: std::sync::OnceLock::new(),
        seen: Mutex::new(Vec::new()),
    });
    let observer: Arc<dyn MempoolObserver> = recorder.clone();
    let pool = handles.mempool_gateway.pool().clone();
    let gateway = Arc::new(bitcoin_rs_mempool::MempoolGateway::new(
        pool,
        Some(observer),
    ));
    recorder.bind(&gateway);
    handles.mempool_gateway = gateway;

    let followers = crate::chain_effects::ChainFollowers::noop();
    crate::reorg::invalidate_block(&handles, &followers, tip_hash)
        .unwrap_or_else(|error| panic!("invalidate tip: {error}"));

    // The spend must have been readmitted to the mempool.
    assert!(
        handles.mempool.read().contains_txid(&spend_txid),
        "the disconnected spend must be readmitted"
    );
    // Every observer mutation during reconsideration must have seen an odd
    // generation (None). If reconsideration ran after proof.finish(), the
    // generation would be even and the recorder would see Some(_).
    let seen = recorder.seen.lock();
    assert!(
        !seen.is_empty(),
        "reconsideration must produce at least one mempool mutation"
    );
    assert!(
        seen.iter().all(|&g| g.is_none()),
        "reconsideration must run while the chain transition is held (odd generation), \
         got {:?}",
        *seen
    );
    // After invalidation completes, the generation is even again
    // (admission reopens). The exact value depends on how many chain
    // changes preceded this call.
    assert!(
        handles.mempool_gateway.stable_generation().is_some(),
        "generation must be even after successful invalidation"
    );
}

#[test]
fn failed_connect_does_not_restore_even_generation() {
    use bitcoin_rs_primitives::{Amount, LockTime, Script, Sequence, Witness};
    let (handles, genesis, _genesis_hash) = setup_regtest_with_genesis();

    // Build a block that will fail during apply — it has a non-coinbase
    // transaction spending a nonexistent UTXO, which will fail consensus.
    let mut bad_tx = Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(
                Txid::from(bitcoin_rs_primitives::Hash256::from_le_bytes(&[0xAA; 32])),
                0,
            ),
            script_sig: Script::new(),
            sequence: Sequence::from_consensus(u32::MAX),
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: Script::new(),
        }],
        lock_time: LockTime::from_consensus(0),
    };
    let _ = &mut bad_tx;

    let block = mined_block_with_prev_hash_and_transactions(
        genesis.block_hash(),
        vec![coinbase_transaction(1), bad_tx],
    )
    .unwrap_or_else(|error| panic!("mine block: {error}"));

    let result = handles.apply_block(&block).map(|outcome| outcome.tip);
    assert!(
        result.is_err(),
        "block with nonexistent UTXO spend must fail"
    );

    // A failed connect leaves the generation odd — admission stays closed.
    assert_eq!(
        handles.mempool_gateway.stable_generation(),
        None,
        "failed connect leaves generation odd (admission closed)"
    );
}
