//! Focused behavioral tests for the node-owned mining coordinator.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use bitcoin_rs_node::{MiningCoordinator, Network, NodeConfig, state::NodeState};
use bitcoin_rs_primitives::encode::double_sha256;
use bitcoin_rs_primitives::{Block, BlockHash, Hash256, Header, OutPoint, Tx, TxIn, TxOut, Txid};
use bitcoin_rs_rpc::context::{
    BlockTemplateMode, BlockTemplateRequest, BlockTemplateResult, BlockValidationResult,
    MiningControl, MiningControlError,
};
use compact_str::CompactString;
use crossbeam_channel::bounded;
use parking_lot::Mutex;

fn open_regtest() -> anyhow::Result<NodeState> {
    let dir = tempfile::tempdir()?;
    let mut config = NodeConfig::default_for_network(Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    // Keep the tempdir alive for the process lifetime of this test by leaking it.
    // NodeState retains open files under data_dir for the test duration.
    std::mem::forget(dir);
    NodeState::open(config, None)
}

fn coordinator(state: &NodeState) -> MiningCoordinator {
    // Empty template coinbase script matches transport-only GBT wiring.
    MiningCoordinator::new(
        state.config().network,
        state.applied_tip(),
        state.block_tree(),
        state.mempool(),
        state.apply_handles(),
        Vec::new(),
        state.shutdown(),
    )
    .with_mempool_update_wait(Duration::ZERO)
}

fn apply_genesis(state: &NodeState) -> anyhow::Result<()> {
    let genesis = Network::Regtest.genesis_block();
    let _ = state.apply_block(&genesis)?;
    Ok(())
}

fn advance_mempool_sequence(state: &NodeState) -> anyhow::Result<()> {
    let mempool = state.mempool();
    let mut guard = mempool.write();
    guard
        .insert_entry(bitcoin_rs_mempool::MempoolEntry::new(
            Arc::new(mempool_sequence_tx()),
            100,
            10_000,
            1,
            7,
        ))
        .map_err(|error| anyhow::anyhow!("seed insert failed: {error}"))?;
    guard.clear();
    Ok(())
}

fn open_network(network: Network) -> anyhow::Result<NodeState> {
    let dir = tempfile::tempdir()?;
    let mut config = NodeConfig::default_for_network(network);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    std::mem::forget(dir);
    NodeState::open(config, None)
}

fn apply_genesis_for(state: &NodeState, network: Network) -> anyhow::Result<()> {
    let genesis = network.genesis_block();
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

/// Lowercase hex, matching the retained wire-seam hex formatting the challenge
/// assertion compares against.
fn to_lower_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn mined_child(prev: BlockHash) -> anyhow::Result<Block> {
    mined_child_labeled(prev, 1)
}

fn mined_child_labeled(prev: BlockHash, label: i64) -> anyhow::Result<Block> {
    let script_opcode = u8::try_from(label + 0x50)?;
    let coinbase = Tx {
        version: 2,
        lock_time: 0,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(Txid::default(), u32::MAX),
            script_sig: vec![script_opcode, 0x51],
            sequence: u32::MAX,
            witness: Vec::new(),
        }],
        outputs: vec![TxOut {
            value: 50 * 100_000_000,
            script_pubkey: vec![0x51],
        }],
    };
    let mut block = Block {
        header: Header {
            version: 0x2000_0000,
            prev_blockhash: prev,
            merkle_root: Hash256::default(),
            time: 1_296_688_603 + 600,
            bits: 0x207f_ffff,
            nonce: 0,
        },
        txs: vec![coinbase],
    };
    block.header.merkle_root = block.txs[0].txid().into();
    mine_block_to_regtest_target(&mut block)?;
    Ok(block)
}

fn mine_block_to_regtest_target(block: &mut Block) -> anyhow::Result<()> {
    while !pow_met(block.header.bits, &block.block_hash()) {
        block.header.nonce = block
            .header
            .nonce
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("nonce exhausted"))?;
    }
    Ok(())
}

/// Consensus merkle root over the block's txids: pairwise double-SHA256 with
/// the last leaf duplicated on odd levels.
fn block_merkle_root(block: &Block) -> Hash256 {
    let mut leaves: Vec<[u8; 32]> = block.txs.iter().map(|tx| *tx.txid().as_bytes()).collect();
    while leaves.len() > 1 {
        let original_len = leaves.len();
        let mut next = Vec::with_capacity(original_len.div_ceil(2));
        for pos in 0..original_len.div_ceil(2) {
            let left = leaves[2 * pos];
            let right = leaves[(2 * pos + 1).min(original_len - 1)];
            let mut pair = [0_u8; 64];
            pair[..32].copy_from_slice(&left);
            pair[32..].copy_from_slice(&right);
            next.push(double_sha256(&pair).to_le_bytes());
        }
        leaves = next;
    }
    Hash256::from_le_bytes(&leaves[0])
}

/// Decodes a 256-bit compact target into little-endian bytes. Negative,
/// overflowed, and zero-mantissa encodings decode to an unreachable zero.
fn compact_to_target(bits: u32) -> [u8; 32] {
    let exponent = usize::from(u8::try_from(bits >> 24).unwrap_or(0));
    let mantissa = u64::from(bits & 0x007f_ffff);
    let mut target = [0_u8; 32];
    if mantissa == 0 || bits & 0x0080_0000 != 0 || exponent > 34 {
        return target;
    }
    let mantissa_bytes = mantissa.to_le_bytes();
    if exponent >= 3 {
        let offset = exponent - 3;
        for (index, byte) in mantissa_bytes.iter().enumerate().take(3) {
            if let Some(slot) = target.get_mut(offset + index) {
                *slot = *byte;
            }
        }
    } else {
        let shifted = mantissa >> (8 * (3 - exponent));
        target[..8].copy_from_slice(&shifted.to_le_bytes());
    }
    target
}

/// Returns true when `hash` is at or below the compact target, comparing the
/// little-endian byte arrays from the most significant end.
fn pow_met(bits: u32, hash: &BlockHash) -> bool {
    let target = compact_to_target(bits);
    let hash_le = hash.as_bytes();
    for index in (0..32).rev() {
        match hash_le[index].cmp(&target[index]) {
            std::cmp::Ordering::Less => return true,
            std::cmp::Ordering::Greater => return false,
            std::cmp::Ordering::Equal => {}
        }
    }
    true
}

/// Fixture transaction whose admission is one emitted mempool change, so
/// sequence-change fixtures observe a real mutation instead of a no-op.
fn mempool_sequence_tx() -> Tx {
    Tx {
        version: 2,
        lock_time: 0,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&[0x42; 32])), 0),
            script_sig: Vec::new(),
            sequence: u32::MAX,
            witness: Vec::new(),
        }],
        outputs: vec![TxOut {
            value: 1_000,
            script_pubkey: vec![0x51],
        }],
    }
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

    advance_mempool_sequence(&state)?;
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
    let genesis = Network::Regtest.genesis_block();
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
    let child_hash = Hash256::from_le_bytes(child.block_hash().as_bytes());
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
    advance_mempool_sequence(&state)?;
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

    let genesis = Network::Regtest.genesis_block();
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
    let genesis = Network::Regtest.genesis_block();
    let child = mined_child(genesis.block_hash())?;
    let child_hash = child.block_hash();
    let result = mining.submit_block(child)?;
    assert_eq!(result, BlockValidationResult::Accepted);
    let tip = state
        .applied_tip()
        .load_full()
        .unwrap_or_else(|| panic!("applied tip missing after submit"));
    assert_eq!(tip.hash, Hash256::from(child_hash));
    assert_eq!(tip.height, 1);
    Ok(())
}

#[test]
fn rejection_mapping_for_bad_prev_hash() -> anyhow::Result<()> {
    let state = open_regtest()?;
    apply_genesis(&state)?;
    let mining = coordinator(&state);
    let mut block = mined_child(BlockHash::from(Hash256::from_le_bytes(&[0x11; 32])))?;
    // Ensure PoW still valid for the mutated prev hash by remine.
    block.header.merkle_root = block_merkle_root(&block);
    block.header.nonce = 0;
    while !pow_met(block.header.bits, &block.block_hash()) {
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
            Vec::new(),
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
            Vec::new(),
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
    apply_genesis_for(&state, Network::Signet)?;
    let mining = coordinator(&state);
    let info = mining.mining_info()?;
    let Some(signet) = info.signet.as_ref() else {
        panic!("default Signet did not expose challenge metadata");
    };
    assert_eq!(
        to_lower_hex(&signet.challenge),
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
    let genesis = Network::Regtest.genesis_block();
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
    let genesis = Network::Regtest.genesis_block();
    let mut block = mined_child(genesis.block_hash())?;
    while pow_met(block.header.bits, &block.block_hash()) {
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
    let genesis = Network::Regtest.genesis_block();
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

    let tx = Tx {
        version: 2,
        lock_time: 0,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&[0x42; 32])), 0),
            script_sig: Vec::new(),
            sequence: u32::MAX,
            witness: Vec::new(),
        }],
        outputs: vec![TxOut {
            value: 1_000,
            script_pubkey: vec![0x51],
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
    let genesis = Network::Regtest.genesis_block();
    let genesis_hash = genesis.block_hash();
    let invalid = mined_child_labeled(genesis.block_hash(), 2)?;
    {
        let tree = state.block_tree();
        let genesis_id = tree
            .read()
            .lookup(Hash256::from(genesis_hash))
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
    let genesis = Network::Regtest.genesis_block();
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
    let genesis = Network::Regtest.genesis_block();
    let genesis_hash = Hash256::from_le_bytes(genesis.block_hash().as_bytes());
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

// ---------------------------------------------------------------------------
// Acceptance tests: mempool-sequence wake remainder (ING-R5)
// ---------------------------------------------------------------------------
//
// `publish_generation_from` builds the generation key from `applied_tip` plus
// a caller-supplied sequence and never takes the mempool read lock. The
// mempool observer routes through it to avoid a reentrant pool read that can
// deadlock under the gateway's publish mutex. Long-poll waiters must return
// immediately on that wake, not wait LONG_POLL_SLICE (1 s).

/// Two threads looping `publish_generation` (tip path) and
/// `publish_generation_from` (mempool path) must not deadlock within a 200 ms
/// watchdog.
#[test]
fn concurrent_publish_generation_paths_do_not_deadlock() -> anyhow::Result<()> {
    let state = open_regtest()?;
    apply_genesis(&state)?;
    let mining = Arc::new(coordinator(&state));

    let stop = Arc::new(AtomicBool::new(false));

    let mining_tip = Arc::clone(&mining);
    let stop_tip = Arc::clone(&stop);
    let tip_thread = thread::spawn(move || {
        while !stop_tip.load(Ordering::Relaxed) {
            mining_tip.publish_generation();
        }
    });

    let mining_seq = Arc::clone(&mining);
    let stop_seq = Arc::clone(&stop);
    let seq_thread = thread::spawn(move || {
        let mut seq = 1_u64;
        while !stop_seq.load(Ordering::Relaxed) {
            mining_seq.publish_generation_from(seq);
            seq = seq.wrapping_add(1);
        }
    });

    // 200 ms watchdog — if either thread is stuck, the joins below time out.
    thread::sleep(Duration::from_millis(200));
    stop.store(true, Ordering::Relaxed);

    tip_thread
        .join()
        .unwrap_or_else(|_| panic!("tip publish_generation thread deadlocked"));
    seq_thread
        .join()
        .unwrap_or_else(|_| panic!("sequence publish_generation_from thread deadlocked"));
    Ok(())
}

/// `publish_generation_from` must not take the mempool read lock: holding the
/// pool write lock and calling it must return immediately, not deadlock.
#[test]
fn publish_generation_from_does_not_take_mempool_lock() -> anyhow::Result<()> {
    let state = open_regtest()?;
    apply_genesis(&state)?;
    let mining = coordinator(&state);

    // Hold the mempool write lock for the duration of the call — a reentrant
    // read would deadlock (parking_lot RwLock is not reentrant).
    let mempool = state.mempool();
    let _write_guard = mempool.write();

    let (done_tx, done_rx) = bounded::<()>(1);
    let handle = thread::spawn(move || {
        mining.publish_generation_from(1);
        let _ = done_tx.send(());
    });

    done_rx
        .recv_timeout(Duration::from_millis(200))
        .map_err(|_| {
            anyhow::anyhow!(
                "publish_generation_from deadlocked under the mempool write lock \
                 — it must not take the mempool read lock"
            )
        })?;
    handle
        .join()
        .unwrap_or_else(|_| panic!("publish_generation_from thread panicked"));
    Ok(())
}

/// A long-poll waiter must return in well under 1 s after a mempool-sequence
/// wake, even when `mempool_update_wait` is non-zero. The waiter returns as
/// soon as the published generation key differs from the waited key — no
/// `LONG_POLL_SLICE` (1 s) recheck delay.
#[test]
fn long_poll_returns_quickly_on_mempool_sequence_wake() -> anyhow::Result<()> {
    let state = open_regtest()?;
    apply_genesis(&state)?;

    // Non-zero cooldown: the old code would wait up to `mempool_update_wait`
    // before returning on a mempool-only change. The fix returns immediately.
    let mining = Arc::new(
        MiningCoordinator::new(
            state.config().network,
            state.applied_tip(),
            state.block_tree(),
            state.mempool(),
            state.apply_handles(),
            Vec::new(),
            state.shutdown(),
        )
        .with_mempool_update_wait(Duration::from_secs(10)),
    );
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

    // Advance the mempool sequence and wake via the lock-free path.
    advance_mempool_sequence(&state)?;
    let seq = state.mempool().read().sequence_number();
    mining.publish_generation_from(seq);

    let wake_start = std::time::Instant::now();
    let result = waiter
        .join()
        .unwrap_or_else(|_| panic!("mempool long-poll waiter panicked"))
        .unwrap_or_else(|error| panic!("mempool long poll failed: {error}"));
    let elapsed = wake_start.elapsed();

    assert!(
        elapsed < Duration::from_millis(800),
        "long-poll waiter returned in {elapsed:?}, expected well under 1 s"
    );
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
