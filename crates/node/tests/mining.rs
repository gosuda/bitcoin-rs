//! Focused behavioral tests for the node-owned mining coordinator.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use bitcoin::ScriptBuf;
use bitcoin::hashes::Hash as _;
use bitcoin_rs_node::{Config, MiningCoordinator, Network, state::NodeState};
use bitcoin_rs_rpc::context::{
    BlockTemplateMode, BlockTemplateRequest, BlockTemplateResult, BlockValidationResult,
    MiningControl, MiningControlError,
};
use compact_str::CompactString;
use crossbeam_channel::bounded;
use parking_lot::Mutex;

fn open_regtest() -> anyhow::Result<NodeState> {
    let dir = tempfile::tempdir()?;
    let mut config = Config::default_for_network(Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p_listen.clear();
    // Keep the tempdir alive for the process lifetime of this test by leaking it.
    // NodeState retains open files under data_dir for the test duration.
    std::mem::forget(dir);
    NodeState::open(config)
}

fn coordinator(state: &NodeState) -> MiningCoordinator {
    // Empty template coinbase script matches transport-only GBT wiring.
    MiningCoordinator::new(
        state.config().network,
        state.applied_tip(),
        state.block_tree(),
        state.mempool(),
        state.apply_handles(),
        ScriptBuf::new(),
        state.shutdown(),
    )
    .with_mempool_update_wait(Duration::ZERO)
}

fn apply_genesis(state: &NodeState) -> anyhow::Result<()> {
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    let _ = state.apply_block(&genesis)?;
    Ok(())
}

fn open_network(network: Network) -> anyhow::Result<NodeState> {
    let dir = tempfile::tempdir()?;
    let mut config = Config::default_for_network(network);
    config.data_dir = dir.path().join("node");
    config.p2p_listen.clear();
    std::mem::forget(dir);
    NodeState::open(config)
}

fn apply_genesis_for(state: &NodeState, network: bitcoin::Network) -> anyhow::Result<()> {
    let genesis = bitcoin::blockdata::constants::genesis_block(network);
    let _ = state.apply_block(&genesis)?;
    Ok(())
}

fn template_request(long_poll_id: Option<CompactString>) -> BlockTemplateRequest {
    BlockTemplateRequest {
        mode: BlockTemplateMode::Template,
        capabilities: Vec::new(),
        rules: Vec::new(),
        long_poll_id,
    }
}

fn expect_template(result: BlockTemplateResult) -> bitcoin_rs_rpc::context::BlockTemplate {
    match result {
        BlockTemplateResult::Template(template) => template,
        other @ BlockTemplateResult::Proposal(_) => {
            panic!("expected template, got {other:?}")
        }
    }
}

fn mined_child(prev: bitcoin::BlockHash) -> anyhow::Result<bitcoin::Block> {
    mined_child_labeled(prev, 1)
}

fn mined_child_labeled(prev: bitcoin::BlockHash, label: i64) -> anyhow::Result<bitcoin::Block> {
    let coinbase = bitcoin::Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![bitcoin::TxIn {
            previous_output: bitcoin::OutPoint::null(),
            script_sig: bitcoin::script::Builder::new()
                .push_int(label)
                .push_int(1)
                .into_script(),
            sequence: bitcoin::Sequence::MAX,
            witness: bitcoin::Witness::new(),
        }],
        output: vec![bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(50 * 100_000_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let mut block = bitcoin::Block {
        header: bitcoin::block::Header {
            version: bitcoin::block::Version::from_consensus(0x2000_0000),
            prev_blockhash: prev,
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time: 1_296_688_603 + 600,
            bits: bitcoin::pow::CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        },
        txdata: vec![coinbase],
    };
    block.header.merkle_root = block
        .compute_merkle_root()
        .ok_or_else(|| anyhow::anyhow!("missing merkle root"))?;
    let target = block.header.target();
    while block.header.validate_pow(target).is_err() {
        block.header.nonce = block
            .header
            .nonce
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("nonce exhausted"))?;
    }
    Ok(block)
}

#[test]
fn cache_reuses_candidate_for_identical_generation_key() -> anyhow::Result<()> {
    let state = open_regtest()?;
    apply_genesis(&state)?;
    let mining = coordinator(&state);
    mining.publish_generation();

    let first = expect_template(mining.get_block_template(template_request(None))?);
    let second = expect_template(mining.get_block_template(template_request(None))?);
    assert_eq!(
        first.candidate.template_id.as_str(),
        second.candidate.template_id.as_str()
    );
    assert!(
        Arc::ptr_eq(&first.candidate, &second.candidate),
        "identical generation must reuse the cached candidate arc"
    );
    Ok(())
}

#[test]
fn key_invalidation_rebuilds_after_mempool_sequence_change() -> anyhow::Result<()> {
    let state = open_regtest()?;
    apply_genesis(&state)?;
    let mining = coordinator(&state);
    mining.publish_generation();
    let first = expect_template(mining.get_block_template(template_request(None))?);

    {
        let mempool = state.mempool();
        let mut guard = mempool.write();
        guard.clear();
    }
    mining.publish_generation();
    let second = expect_template(mining.get_block_template(template_request(None))?);
    assert_ne!(
        first.candidate.template_id.as_str(),
        second.candidate.template_id.as_str(),
        "mempool sequence change must invalidate the generation key"
    );
    assert!(!Arc::ptr_eq(&first.candidate, &second.candidate));
    Ok(())
}

#[test]
fn concurrent_requests_share_single_flight_assembly() -> anyhow::Result<()> {
    let state = open_regtest()?;
    apply_genesis(&state)?;
    let mining = Arc::new(coordinator(&state));
    mining.publish_generation();

    let barrier = Arc::new(std::sync::Barrier::new(8));
    let candidates = Arc::new(Mutex::new(Vec::new()));
    let mut handles = Vec::new();
    for _ in 0..8 {
        let mining = Arc::clone(&mining);
        let barrier = Arc::clone(&barrier);
        let candidates = Arc::clone(&candidates);
        handles.push(thread::spawn(move || {
            barrier.wait();
            let template = expect_template(
                mining
                    .get_block_template(template_request(None))
                    .unwrap_or_else(|error| panic!("template failed: {error}")),
            );
            candidates.lock().push(Arc::clone(&template.candidate));
        }));
    }
    for handle in handles {
        handle.join().unwrap_or_else(|_| panic!("worker panicked"));
    }
    let candidates = candidates.lock();
    let first = &candidates[0];
    assert!(
        candidates
            .iter()
            .all(|candidate| Arc::ptr_eq(candidate, first)),
        "all concurrent waiters must observe the same single-flight candidate"
    );
    Ok(())
}

#[test]
fn long_poll_wakes_on_tip_change() -> anyhow::Result<()> {
    let state = open_regtest()?;
    apply_genesis(&state)?;
    let mining = Arc::new(coordinator(&state));
    mining.publish_generation();
    let current = expect_template(mining.get_block_template(template_request(None))?);
    let long_poll_id = CompactString::from(current.candidate.template_id.as_str());
    let (started_tx, started_rx) = bounded::<()>(1);
    let mining_wait = Arc::clone(&mining);
    let waiter = thread::spawn(move || {
        started_tx
            .send(())
            .unwrap_or_else(|error| panic!("start signal failed: {error}"));
        mining_wait.get_block_template(template_request(Some(long_poll_id)))
    });
    started_rx.recv_timeout(Duration::from_secs(2))?;
    thread::sleep(Duration::from_millis(50));
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    let child = mined_child(genesis.block_hash())?;
    let _ = state.apply_block(&child)?;
    mining.publish_generation();
    let result = waiter
        .join()
        .unwrap_or_else(|_| panic!("long-poll waiter panicked"))
        .unwrap_or_else(|error| panic!("long poll failed: {error}"));
    let template = expect_template(result);
    assert_ne!(
        template.candidate.template_id.as_str(),
        current.candidate.template_id.as_str()
    );
    let child_hash =
        bitcoin_rs_primitives::Hash256::from_le_bytes(child.block_hash().as_byte_array());
    assert_eq!(template.candidate.previous_block_hash, child_hash);
    assert_eq!(template.submit_old, Some(false));
    assert_eq!(
        template.rules.iter().any(|rule| rule.as_str() == "csv"),
        template.candidate.csv_active
    );
    assert_eq!(
        template.rules.iter().any(|rule| rule.as_str() == "segwit"),
        template.candidate.segwit_active
    );
    Ok(())
}

#[test]
fn long_poll_wakes_on_mempool_sequence_change() -> anyhow::Result<()> {
    let state = open_regtest()?;
    apply_genesis(&state)?;
    let mining = Arc::new(coordinator(&state));
    mining.publish_generation();
    let current = expect_template(mining.get_block_template(template_request(None))?);
    let long_poll_id = CompactString::from(current.candidate.template_id.as_str());
    let (started_tx, started_rx) = bounded::<()>(1);
    let mining_wait = Arc::clone(&mining);
    let waiter = thread::spawn(move || {
        started_tx
            .send(())
            .unwrap_or_else(|error| panic!("start signal failed: {error}"));
        mining_wait.get_block_template(template_request(Some(long_poll_id)))
    });
    started_rx.recv_timeout(Duration::from_secs(2))?;
    thread::sleep(Duration::from_millis(50));
    {
        let mempool = state.mempool();
        let mut guard = mempool.write();
        guard.clear();
    }
    mining.publish_generation();
    let result = waiter
        .join()
        .unwrap_or_else(|_| panic!("mempool long-poll waiter panicked"))
        .unwrap_or_else(|error| panic!("mempool long poll failed: {error}"));
    let template = expect_template(result);
    assert_ne!(
        template.candidate.mempool_sequence,
        current.candidate.mempool_sequence
    );
    assert_eq!(
        template.candidate.previous_block_hash,
        current.candidate.previous_block_hash
    );
    assert_eq!(template.submit_old, Some(true));
    Ok(())
}

#[test]
fn proposal_has_no_side_effects() -> anyhow::Result<()> {
    let state = open_regtest()?;
    apply_genesis(&state)?;
    let mining = coordinator(&state);
    mining.publish_generation();
    let before = state
        .applied_tip()
        .load_full()
        .unwrap_or_else(|| panic!("applied tip missing before proposal"));
    let before_seq = state.mempool().read().sequence_number();
    let before_blocks = state.blocks().read().len();

    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    let child = mined_child(genesis.block_hash())?;
    let result = mining.get_block_template(BlockTemplateRequest {
        mode: BlockTemplateMode::Proposal(child),
        capabilities: Vec::new(),
        rules: Vec::new(),
        long_poll_id: None,
    })?;
    match result {
        BlockTemplateResult::Proposal(
            BlockValidationResult::Accepted | BlockValidationResult::Rejected(_),
        ) => {}
        other => panic!("expected proposal result, got {other:?}"),
    }

    let after = state
        .applied_tip()
        .load_full()
        .unwrap_or_else(|| panic!("applied tip missing after proposal"));
    assert_eq!(before.hash, after.hash);
    assert_eq!(before_seq, state.mempool().read().sequence_number());
    assert_eq!(before_blocks, state.blocks().read().len());
    Ok(())
}

#[test]
fn accepted_submission_is_visible_before_return() -> anyhow::Result<()> {
    let state = open_regtest()?;
    apply_genesis(&state)?;
    let mining = coordinator(&state);
    mining.publish_generation();
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    let child = mined_child(genesis.block_hash())?;
    let child_hash =
        bitcoin_rs_primitives::Hash256::from_le_bytes(child.block_hash().as_byte_array());
    let result = mining.submit_block(child)?;
    assert_eq!(result, BlockValidationResult::Accepted);
    let tip = state
        .applied_tip()
        .load_full()
        .unwrap_or_else(|| panic!("applied tip missing after submit"));
    assert_eq!(tip.hash, child_hash);
    assert_eq!(tip.height, 1);
    Ok(())
}

#[test]
fn rejection_mapping_for_bad_prev_hash() -> anyhow::Result<()> {
    let state = open_regtest()?;
    apply_genesis(&state)?;
    let mining = coordinator(&state);
    let mut block = mined_child(bitcoin::BlockHash::from_byte_array([0x11; 32]))?;
    // Ensure PoW still valid for the mutated prev hash by remine.
    block.header.merkle_root = block
        .compute_merkle_root()
        .ok_or_else(|| anyhow::anyhow!("missing merkle root"))?;
    let target = block.header.target();
    block.header.nonce = 0;
    while block.header.validate_pow(target).is_err() {
        block.header.nonce = block
            .header
            .nonce
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("nonce exhausted"))?;
    }
    let result = mining.submit_block(block)?;
    match result {
        BlockValidationResult::Rejected(reason) => {
            assert!(
                reason.contains("inconclusive-not-best-prevblk") || reason.contains("prev"),
                "unexpected rejection reason: {reason}"
            );
        }
        other => panic!("expected rejection, got {other:?}"),
    }
    Ok(())
}

#[test]
fn shutdown_wakes_long_poll() -> anyhow::Result<()> {
    let state = open_regtest()?;
    apply_genesis(&state)?;
    let shutdown = Arc::new(AtomicBool::new(false));
    let mining = Arc::new(
        MiningCoordinator::new(
            state.config().network,
            state.applied_tip(),
            state.block_tree(),
            state.mempool(),
            state.apply_handles(),
            ScriptBuf::new(),
            Arc::clone(&shutdown),
        )
        .with_mempool_update_wait(Duration::ZERO),
    );
    mining.publish_generation();
    let current = expect_template(mining.get_block_template(template_request(None))?);
    let long_poll_id = CompactString::from(current.candidate.template_id.as_str());
    let mining_wait = Arc::clone(&mining);
    let waiter =
        thread::spawn(move || mining_wait.get_block_template(template_request(Some(long_poll_id))));
    thread::sleep(Duration::from_millis(50));
    shutdown.store(true, Ordering::Release);
    mining.notify_shutdown();
    let outcome = waiter
        .join()
        .unwrap_or_else(|_| panic!("shutdown waiter panicked"));
    let Err(err) = outcome else {
        panic!("shutdown wait unexpectedly succeeded");
    };
    assert!(matches!(err, MiningControlError::Unavailable(_)));
    Ok(())
}

#[test]
fn shutdown_exits_long_poll_without_direct_wake() -> anyhow::Result<()> {
    let state = open_regtest()?;
    apply_genesis(&state)?;
    let shutdown = Arc::new(AtomicBool::new(false));
    let mining = Arc::new(
        MiningCoordinator::new(
            state.config().network,
            state.applied_tip(),
            state.block_tree(),
            state.mempool(),
            state.apply_handles(),
            ScriptBuf::new(),
            Arc::clone(&shutdown),
        )
        .with_mempool_update_wait(Duration::ZERO),
    );
    mining.publish_generation();
    let current = expect_template(mining.get_block_template(template_request(None))?);
    let long_poll_id = CompactString::from(current.candidate.template_id.as_str());
    let mining_wait = Arc::clone(&mining);
    let waiter =
        thread::spawn(move || mining_wait.get_block_template(template_request(Some(long_poll_id))));
    thread::sleep(Duration::from_millis(50));
    // Bounded wait slices must observe the flag even without notify_shutdown.
    shutdown.store(true, Ordering::Release);
    let outcome = waiter
        .join()
        .unwrap_or_else(|_| panic!("bounded shutdown waiter panicked"));
    let Err(err) = outcome else {
        panic!("bounded shutdown wait unexpectedly succeeded");
    };
    assert!(matches!(err, MiningControlError::Unavailable(_)));
    Ok(())
}

#[test]
fn mining_info_reports_default_signet_challenge() -> anyhow::Result<()> {
    let state = open_network(Network::Signet)?;
    apply_genesis_for(&state, bitcoin::Network::Signet)?;
    let mining = coordinator(&state);
    let info = mining.mining_info()?;
    let Some(signet) = info.signet.as_ref() else {
        panic!("default Signet did not expose challenge metadata");
    };
    assert_eq!(
        signet.challenge.to_hex_string(),
        concat!(
            "512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430",
            "210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c452ae",
        )
    );
    Ok(())
}

#[test]
fn mining_info_omits_signet_on_regtest() -> anyhow::Result<()> {
    let state = open_regtest()?;
    apply_genesis(&state)?;
    let mining = coordinator(&state);
    let info = mining.mining_info()?;
    assert!(info.signet.is_none());
    Ok(())
}

#[test]
fn duplicate_submit_returns_duplicate() -> anyhow::Result<()> {
    let state = open_regtest()?;
    apply_genesis(&state)?;
    let mining = coordinator(&state);
    mining.publish_generation();
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    let child = mined_child(genesis.block_hash())?;
    assert_eq!(
        mining.submit_block(child.clone())?,
        BlockValidationResult::Accepted
    );
    assert_eq!(
        mining.submit_block(child)?,
        BlockValidationResult::Duplicate
    );
    Ok(())
}

#[test]
fn unsolved_pow_is_rejected_by_proposal_and_submit() -> anyhow::Result<()> {
    let state = open_regtest()?;
    apply_genesis(&state)?;
    let mining = coordinator(&state);
    mining.publish_generation();
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    let mut block = mined_child(genesis.block_hash())?;
    let target = block.header.target();
    while block.header.validate_pow(target).is_ok() {
        block.header.nonce = block
            .header
            .nonce
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("nonce exhausted while invalidating PoW"))?;
    }
    let proposal = mining.get_block_template(BlockTemplateRequest {
        mode: BlockTemplateMode::Proposal(block.clone()),
        capabilities: Vec::new(),
        rules: Vec::new(),
        long_poll_id: None,
    })?;
    match proposal {
        BlockTemplateResult::Proposal(BlockValidationResult::Accepted) => {}
        other => panic!("BIP22 proposal must omit unsolved PoW, got {other:?}"),
    }
    match mining.submit_block(block)? {
        BlockValidationResult::Rejected(reason) => {
            assert!(reason.contains("high-hash"), "submit reason: {reason}");
        }
        other => panic!("expected submit high-hash, got {other:?}"),
    }
    Ok(())
}

#[test]
fn duplicate_solved_submission_is_idempotent() -> anyhow::Result<()> {
    let state = open_regtest()?;
    apply_genesis(&state)?;
    let mining = coordinator(&state);
    mining.publish_generation();
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    let child = mined_child(genesis.block_hash())?;
    assert_eq!(
        mining.submit_block(child.clone())?,
        BlockValidationResult::Accepted
    );
    let height = state.applied_tip().load_full().map_or(0, |tip| tip.height);
    assert_eq!(
        mining.submit_block(child)?,
        BlockValidationResult::Duplicate
    );
    assert_eq!(
        state.applied_tip().load_full().map_or(0, |tip| tip.height),
        height,
        "duplicate solved submission must not reapply"
    );
    Ok(())
}

#[test]
fn mining_info_reports_network_hashps_after_genesis() -> anyhow::Result<()> {
    let state = open_regtest()?;
    apply_genesis(&state)?;
    let mining = coordinator(&state);
    let info = mining.mining_info()?;
    assert_eq!(info.blocks, 0);
    assert!(
        info.network_hashes_per_second.is_finite(),
        "hashps must be a finite projection"
    );
    Ok(())
}

#[test]
fn currentblocktx_excludes_coinbase_for_zero_and_one() -> anyhow::Result<()> {
    use bitcoin::{
        Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Txid, Witness, absolute, transaction,
    };
    use bitcoin_rs_mempool::MempoolEntry;

    let state = open_regtest()?;
    apply_genesis(&state)?;
    let mining = coordinator(&state);
    mining.publish_generation();
    let empty = expect_template(mining.get_block_template(template_request(None))?);
    let empty_info = mining.mining_info()?;
    assert!(empty.candidate.transactions.is_empty());
    assert_eq!(
        empty_info.last_candidate.map(|info| info.transactions),
        Some(0)
    );

    let tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(Txid::from_byte_array([0x42; 32]), 0),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    {
        let mempool = state.mempool();
        let mut guard = mempool.write();
        guard.insert_entry(MempoolEntry::new(Arc::new(tx), 120, 10_000, 1, 1))?;
    }
    mining.publish_generation();
    let one = expect_template(mining.get_block_template(template_request(None))?);
    let one_info = mining.mining_info()?;
    assert_eq!(one.candidate.transactions.len(), 1);
    assert_eq!(
        one_info.last_candidate.map(|info| info.transactions),
        Some(1)
    );
    Ok(())
}

#[test]
fn known_invalid_submit_is_duplicate_invalid() -> anyhow::Result<()> {
    use bitcoin_rs_chain::NodeStatus;
    use bitcoin_rs_primitives::Hash256;

    let state = open_regtest()?;
    apply_genesis(&state)?;
    let mining = coordinator(&state);
    mining.publish_generation();
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    let genesis_hash = Hash256::from_le_bytes(genesis.block_hash().as_byte_array());
    let invalid = mined_child_labeled(genesis.block_hash(), 2)?;
    {
        let tree = state.block_tree();
        let genesis_id = tree
            .read()
            .lookup(genesis_hash)
            .ok_or_else(|| anyhow::anyhow!("missing genesis"))?;
        tree.write()
            .insert_node(Some(genesis_id), invalid.header, NodeStatus::Invalid)?;
    }
    assert_eq!(
        mining.submit_block(invalid)?,
        BlockValidationResult::DuplicateInvalid
    );
    Ok(())
}

#[test]
fn active_ancestor_submit_is_duplicate() -> anyhow::Result<()> {
    let state = open_regtest()?;
    apply_genesis(&state)?;
    let mining = coordinator(&state);
    mining.publish_generation();
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    let child = mined_child(genesis.block_hash())?;
    assert_eq!(mining.submit_block(child)?, BlockValidationResult::Accepted);
    assert_eq!(
        mining.submit_block(genesis)?,
        BlockValidationResult::Duplicate
    );
    Ok(())
}

#[test]
fn known_non_active_submit_is_duplicate_inconclusive() -> anyhow::Result<()> {
    use bitcoin_rs_chain::NodeStatus;
    use bitcoin_rs_primitives::Hash256;

    let state = open_regtest()?;
    apply_genesis(&state)?;
    let mining = coordinator(&state);
    mining.publish_generation();
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    let genesis_hash = Hash256::from_le_bytes(genesis.block_hash().as_byte_array());
    let side = mined_child_labeled(genesis.block_hash(), 3)?;
    {
        let tree = state.block_tree();
        let genesis_id = tree
            .read()
            .lookup(genesis_hash)
            .ok_or_else(|| anyhow::anyhow!("missing genesis"))?;
        tree.write()
            .insert_node(Some(genesis_id), side.header, NodeStatus::HeaderValid)?;
    }
    assert_eq!(
        mining.submit_block(side)?,
        BlockValidationResult::DuplicateInconclusive
    );
    Ok(())
}
