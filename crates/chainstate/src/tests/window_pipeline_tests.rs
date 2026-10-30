use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::Mutex;

use bitcoin_rs_chain::regtest_fixture::{
    merkle_root, mine_block_to_declared_target, mined_regtest_child_at as mined_child,
    mined_regtest_child_at_time as mined_child_at_time,
};
use bitcoin_rs_chain::{ChainTxCount, NodeId};
use bitcoin_rs_primitives::{
    Amount, Block, BlockHash, BlockPayload, Hash256, LockTime, Network, OutPoint, Script, Sequence,
    Tx, TxIn, TxOut, Txid, Witness,
};
use bitcoin_rs_script::opcode::OP_PUSHNUM_1;
use bitcoin_rs_storage::{
    CommitRecords, DurableHead, DurableHeadStore, InMemoryDurableHeadStore, ScriptAttestation,
    StorageError,
};
use bitcoin_rs_utxo::UtxoSet;

use super::{ApplyError, Chainstate, WindowApplyDisposition};
use crate::test_fixtures::{handles, seed_genesis};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The group cap `RCV-02` states: 64 blocks or 8 MiB of block data, whichever first.
const GROUP_BLOCKS: usize = 64;

fn remine(block: &mut Block) -> TestResult {
    block.header.merkle_root = merkle_root(&block.txs).ok_or("test body has no merkle root")?;
    mine_block_to_declared_target(block)?;
    Ok(())
}

fn coinbase_child(prev: BlockHash, height: u32, script: &[u8]) -> TestResult<Block> {
    let mut block = mined_child(prev, height)?;
    block.txs[0].outputs = vec![TxOut {
        value: Amount::from_sat(10_000),
        script_pubkey: Script::from_bytes(script.to_vec()),
    }];
    remine(&mut block)?;
    Ok(block)
}

fn spend_tx(funding: OutPoint, value: u64) -> Tx {
    Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: funding,
            script_sig: vec![OP_PUSHNUM_1].into(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey: vec![OP_PUSHNUM_1].into(),
        }],
        lock_time: LockTime::ZERO,
    }
}

fn block_with_spend(prev: BlockHash, height: u32, spend: Tx) -> TestResult<Block> {
    let mut block = mined_child(prev, height)?;
    block.txs.push(spend);
    remine(&mut block)?;
    Ok(block)
}

fn coinbase_less_block(prev: BlockHash, height: u32, script_len: usize) -> TestResult<Block> {
    let mut block = mined_child(prev, height)?;
    block.txs = vec![Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&[0x42; 32])), 0),
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: Script::from_bytes(vec![OP_PUSHNUM_1; script_len]),
        }],
        lock_time: LockTime::ZERO,
    }];
    remine(&mut block)?;
    Ok(block)
}

fn commit_genesis_head(chain: &Chainstate) -> TestResult {
    let genesis = Network::Regtest.genesis_block();
    chain.durable_head.commit(
        None,
        &DurableHead {
            assumeutxo: bitcoin_rs_storage::assumeutxo::AssumeUtxoDiskStatus::Uninitialized,
            commit_id: 1,
            height: 0,
            tip: Hash256::from(genesis.block_hash()),
            chain_tx_count: 1,
            body_extent: None,
            undo_extent: None,
        },
        &CommitRecords::default(),
    )?;
    Ok(())
}

fn dump_payloads(blocks: &[Block]) -> Vec<BlockPayload> {
    blocks
        .iter()
        .map(|block| BlockPayload::from_local(block.clone()))
        .collect()
}

fn apply_headers(chain: &Chainstate, blocks: &[&Block]) -> TestResult {
    let headers: Vec<_> = blocks.iter().map(|block| block.header).collect();
    chain.admit_headers(&headers)?;
    Ok(())
}

struct CrashOnCommitHead {
    inner: InMemoryDurableHeadStore,
    fail_on_commit: u64,
    attempts: AtomicU64,
}

impl CrashOnCommitHead {
    fn new(fail_on_commit: u64) -> Self {
        Self {
            inner: InMemoryDurableHeadStore::new(),
            fail_on_commit,
            attempts: AtomicU64::new(0),
        }
    }
}

impl DurableHeadStore for CrashOnCommitHead {
    fn load(&self) -> Result<Option<DurableHead>, StorageError> {
        self.inner.load()
    }

    fn load_attestation(&self, head: &DurableHead) -> Result<ScriptAttestation, StorageError> {
        self.inner.load_attestation(head)
    }

    fn attest(&self, head: &DurableHead, level: ScriptAttestation) -> Result<(), StorageError> {
        self.inner.attest(head, level)
    }

    fn commit(
        &self,
        expected: Option<&DurableHead>,
        next: &DurableHead,
        records: &CommitRecords<'_>,
    ) -> Result<(), StorageError> {
        let attempt = self
            .attempts
            .fetch_add(1, Ordering::SeqCst)
            .saturating_add(1);
        if attempt == self.fail_on_commit {
            return Err(StorageError::InvalidOperation(
                "injected durable head commit failure",
            ));
        }
        self.inner.commit(expected, next, records)
    }
}

struct NoopObserver;

impl crate::reorg::ReorgObserver for NoopObserver {
    fn disconnected(&mut self, _: &crate::DisconnectOutcome) {}

    fn connected(&mut self, _: &Block, _: &crate::ConnectOutcome) {}

    fn reconsider_disconnected(&mut self, _: &Block) {}
}

fn node_id(chain: &Chainstate, hash: BlockHash) -> TestResult<NodeId> {
    chain
        .block_tree
        .read()
        .lookup(Hash256::from(hash))
        .ok_or_else(|| format!("header {hash} is missing from the block tree").into())
}

// RCV-02
#[test]
fn a_window_commits_every_block_in_order() -> TestResult {
    let chain = handles(Network::Regtest, Arc::new(UtxoSet::new()));
    seed_genesis(&chain)?;
    commit_genesis_head(&chain)?;

    let mut blocks = Vec::new();
    let mut parent = Network::Regtest.genesis_block().block_hash();
    for height in 1..=3 {
        let block = mined_child(parent, height)?;
        parent = block.block_hash();
        blocks.push(block);
    }
    let refs: Vec<&Block> = blocks.iter().collect();
    apply_headers(&chain, &refs)?;
    let payloads = dump_payloads(&blocks);
    let window: Vec<&BlockPayload> = payloads.iter().collect();

    let outcomes = chain.apply_window(&window)?;

    let expected: Vec<(u32, Hash256)> = blocks
        .iter()
        .enumerate()
        .map(|(index, block)| {
            (
                u32::try_from(index).unwrap_or(u32::MAX) + 1,
                Hash256::from(block.block_hash()),
            )
        })
        .collect();
    let observed: Vec<(u32, Hash256)> = outcomes
        .iter()
        .map(|outcome| (outcome.height, outcome.hash))
        .collect();
    assert_eq!(
        observed, expected,
        "the applied window publishes its blocks in chain order, one outcome per block"
    );
    assert_eq!(
        outcomes[2].tip.chain_tx_count,
        ChainTxCount::established(4),
        "the last outcome carries the cumulative count of every staged block, not a per-block delta"
    );

    let applied = chain
        .applied_tip_snapshot()
        .ok_or("the window publishes a tip")?;
    assert_eq!(
        applied.hash, expected[2].1,
        "the applied tip names the last block of the window"
    );
    let head = chain
        .durable_head
        .load()?
        .ok_or("the window writes a head")?;
    assert_eq!(
        (head.height, head.tip),
        (3, expected[2].1),
        "the durable head names the last block of the window"
    );
    Ok(())
}

// RCV-02
#[test]
fn a_window_commits_a_block_that_spends_the_previous_blocks_output() -> TestResult {
    let chain = handles(Network::Regtest, Arc::new(UtxoSet::new()));
    seed_genesis(&chain)?;
    commit_genesis_head(&chain)?;

    let mut parent = Network::Regtest.genesis_block().block_hash();
    let mut funding = None;
    for height in 1..=u32::try_from(100).expect("literal fits") {
        let block = coinbase_child(parent, height, &[OP_PUSHNUM_1])?;
        if height == 1 {
            funding = Some(OutPoint::new(block.txs[0].txid(), 0));
        }
        chain.apply_block(&BlockPayload::from_local(block.clone()))?;
        parent = block.block_hash();
    }
    let funding = funding.ok_or("the fixture mined the funding coinbase")?;

    let first_spend = spend_tx(funding, 9_000);
    let first_spend_outpoint = OutPoint::new(first_spend.txid(), 0);
    let first = block_with_spend(parent, 101, first_spend)?;
    let second = block_with_spend(
        first.block_hash(),
        102,
        spend_tx(first_spend_outpoint, 8_000),
    )?;
    let blocks = [first, second];
    let refs: Vec<&Block> = blocks.iter().collect();
    apply_headers(&chain, &refs)?;
    let payloads = dump_payloads(&blocks);
    let window: Vec<&BlockPayload> = payloads.iter().collect();

    let outcomes = chain.apply_window(&window)?;

    assert_eq!(outcomes.len(), 2, "both window blocks commit");
    assert_eq!(
        (outcomes[0].height, outcomes[1].height),
        (101, 102),
        "the spending block commits only after the block that funded it"
    );
    assert_eq!(
        outcomes[0].tip.chain_tx_count,
        ChainTxCount::established(103),
        "the funding block counts the 101 earlier transactions plus its own two"
    );
    assert_eq!(
        outcomes[1].tip.chain_tx_count,
        ChainTxCount::established(105),
        "the dependent block spends the funding block's output, so its count builds on 103"
    );
    let applied = chain
        .applied_tip_snapshot()
        .ok_or("the window publishes a tip")?;
    assert_eq!(
        applied.hash,
        Hash256::from(blocks[1].block_hash()),
        "the dependent spend is committed and published as the window tip"
    );
    assert!(
        chain.utxo.get(&first_spend_outpoint).is_none(),
        "the dependent block spends the funding block's output, so that coin leaves the utxo set"
    );
    Ok(())
}

// RCV-02
#[test]
fn a_window_with_an_invalid_middle_block_commits_only_the_valid_prefix() -> TestResult {
    let chain = handles(Network::Regtest, Arc::new(UtxoSet::new()));
    seed_genesis(&chain)?;
    commit_genesis_head(&chain)?;

    let first = mined_child(Network::Regtest.genesis_block().block_hash(), 1)?;
    let second = mined_child(first.block_hash(), 2)?;
    let bad = coinbase_less_block(second.block_hash(), 3, 0)?;
    let trailing = mined_child(bad.block_hash(), 4)?;
    let blocks = [first, second, bad, trailing];
    let refs: Vec<&Block> = blocks.iter().collect();
    apply_headers(&chain, &refs)?;
    let payloads = dump_payloads(&blocks);
    let window: Vec<&BlockPayload> = payloads.iter().collect();

    let error = chain
        .apply_window(&window)
        .err()
        .ok_or("a body without a coinbase must not commit")?;
    assert!(
        matches!(
            error.source,
            ApplyError::Consensus(bitcoin_rs_consensus::ConsensusError::MissingCoinbase)
        ),
        "a body whose only transaction is not a coinbase is rejected as missing its coinbase, got {:?}",
        error.source
    );

    assert_eq!(
        error.applied, 2,
        "only the blocks before the invalid middle block commit"
    );
    let committed: Vec<(u32, Hash256)> = error
        .committed
        .iter()
        .map(|outcome| (outcome.height, outcome.hash))
        .collect();
    assert_eq!(
        committed,
        vec![
            (1, Hash256::from(blocks[0].block_hash())),
            (2, Hash256::from(blocks[1].block_hash())),
        ],
        "the committed prefix is the two valid blocks, in order"
    );
    assert_eq!(
        error.disposition,
        WindowApplyDisposition::Permanent,
        "a body without a coinbase is a permanent body defect"
    );
    let mut invalidated: Vec<Hash256> = error.invalidated.to_vec();
    invalidated.sort_unstable();
    let mut expected_invalidated = vec![
        Hash256::from(blocks[2].block_hash()),
        Hash256::from(blocks[3].block_hash()),
    ];
    expected_invalidated.sort_unstable();
    assert_eq!(
        invalidated, expected_invalidated,
        "the invalid body invalidates its own header subtree, including the trailing block"
    );

    let applied = chain
        .applied_tip_snapshot()
        .ok_or("the prefix publishes a tip")?;
    assert_eq!(
        (applied.height, applied.hash),
        (2, Hash256::from(blocks[1].block_hash())),
        "the applied tip stops at the last valid block of the prefix"
    );
    let head = chain
        .durable_head
        .load()?
        .ok_or("the prefix writes a head")?;
    assert_eq!(
        (head.height, head.tip),
        (2, Hash256::from(blocks[1].block_hash())),
        "the durable head names the last valid block of the prefix, never the invalid one"
    );
    Ok(())
}

// RCV-02
#[test]
fn a_window_prepared_against_a_replaced_tip_discards_the_stale_branch() -> TestResult {
    let mut chain = handles(Network::Regtest, Arc::new(UtxoSet::new()));
    chain.block_body_store = Some(Arc::new(crate::test_fixtures::MemoryBodies::default()));
    seed_genesis(&chain)?;
    commit_genesis_head(&chain)?;
    let genesis = Network::Regtest.genesis_block();
    let genesis_time = genesis.header.time;

    let old_first = mined_child_at_time(genesis.block_hash(), genesis_time + 10, 1)?;
    let old_second = mined_child_at_time(old_first.block_hash(), genesis_time + 11, 2)?;
    let old_second_hash = old_second.block_hash();
    let old_blocks = [old_first, old_second];
    let old_refs: Vec<&Block> = old_blocks.iter().collect();
    apply_headers(&chain, &old_refs)?;
    let old_payloads = dump_payloads(&old_blocks);
    let old_window: Vec<&BlockPayload> = old_payloads.iter().collect();
    chain.apply_window(&old_window)?;

    let new_first = mined_child_at_time(genesis.block_hash(), genesis_time + 20, 1)?;
    let new_second = mined_child_at_time(new_first.block_hash(), genesis_time + 21, 2)?;
    let new_third = mined_child_at_time(new_second.block_hash(), genesis_time + 22, 3)?;
    let new_third_hash = new_third.block_hash();
    let new_blocks = [new_first, new_second, new_third];
    let new_refs: Vec<&Block> = new_blocks.iter().collect();
    apply_headers(&chain, &new_refs)?;
    let new_payloads = dump_payloads(&new_blocks);
    let bodies: HashMap<Hash256, BlockPayload> = new_blocks
        .iter()
        .zip(&new_payloads)
        .map(|(block, payload)| (Hash256::from(block.block_hash()), payload.clone()))
        .collect();
    let target = node_id(&chain, new_third_hash)?;
    crate::reorg::switch_to_branch(
        &chain,
        target,
        |hash| bodies.get(&hash).cloned(),
        &mut NoopObserver,
        |_, outcome| outcome,
    )?;
    let reorged = chain
        .applied_tip_snapshot()
        .ok_or("the branch switch publishes a tip")?;
    assert_eq!(
        reorged.hash,
        Hash256::from(new_third_hash),
        "the reorg moves the applied tip onto the longer branch"
    );

    let successor = mined_child_at_time(new_third_hash, genesis_time + 30, 4)?;
    let stale = mined_child_at_time(old_second_hash, genesis_time + 12, 3)?;
    let mixed = [successor, stale];
    let mixed_refs: Vec<&Block> = mixed.iter().collect();
    apply_headers(&chain, &mixed_refs)?;
    let mixed_payloads = dump_payloads(&mixed);
    let mixed_window: Vec<&BlockPayload> = mixed_payloads.iter().collect();

    let error = chain
        .apply_window(&mixed_window)
        .err()
        .ok_or("a block from the replaced branch cannot extend the new tip")?;

    assert_eq!(
        error.applied, 1,
        "only the block extending the reorged tip commits; the stale block is discarded"
    );
    assert_eq!(
        error.committed.len(),
        1,
        "the stale block is never committed"
    );
    assert_eq!(
        error.committed[0].hash,
        Hash256::from(mixed[0].block_hash()),
        "the committed outcome names the block that extended the reorged tip"
    );
    assert!(
        matches!(error.source, ApplyError::PrevHashMismatch { .. }),
        "the stale block is refused because its predecessor is not the applied tip, got {:?}",
        error.source
    );
    assert_eq!(
        error.disposition,
        WindowApplyDisposition::Operational,
        "a stale predecessor is retryable, not a permanent body defect"
    );
    let applied = chain
        .applied_tip_snapshot()
        .ok_or("the applied tip survives")?;
    assert_eq!(
        applied.hash,
        Hash256::from(mixed[0].block_hash()),
        "the applied tip is the block that extended the reorged chain, not the stale one"
    );
    let head = chain.durable_head.load()?.ok_or("the head survives")?;
    assert_eq!(
        (head.height, head.tip),
        (4, Hash256::from(mixed[0].block_hash())),
        "the durable head names the committed block of the reorged chain"
    );
    Ok(())
}

// RCV-02
#[test]
fn a_window_holds_its_transition_until_a_concurrent_shutdown_acquires_it() -> TestResult {
    let chain = handles(Network::Regtest, Arc::new(UtxoSet::new()));
    seed_genesis(&chain)?;
    commit_genesis_head(&chain)?;

    let mut blocks = Vec::new();
    let mut parent = Network::Regtest.genesis_block().block_hash();
    for height in 1..=3 {
        let block = mined_child(parent, height)?;
        parent = block.block_hash();
        blocks.push(block);
    }
    let refs: Vec<&Block> = blocks.iter().collect();
    apply_headers(&chain, &refs)?;

    let requested = Arc::new(AtomicU64::new(0));
    let closer: Arc<Mutex<Option<std::thread::JoinHandle<()>>>> = Arc::new(Mutex::new(None));
    let hook: crate::TipStagedHook = {
        let chain = chain.clone();
        let requested = Arc::clone(&requested);
        let closer = Arc::clone(&closer);
        Arc::new(
            move |_staged: &bitcoin_rs_chain::TipSnapshot, _block: &Block| {
                let chain = chain.clone();
                let closing = Arc::new(AtomicU64::new(0));
                let closer_flag = Arc::clone(&closing);
                let handle = std::thread::spawn(move || {
                    closer_flag.store(1, Ordering::SeqCst);
                    let _guard = chain.close();
                });
                while closing.load(Ordering::SeqCst) == 0 {
                    std::thread::yield_now();
                }
                requested.fetch_add(1, Ordering::SeqCst);
                closer.lock().replace(handle);
            },
        )
    };
    chain
        .set_tip_staged(hook)
        .map_err(|_| "the staged-tip hook installs once")?;
    let payloads = dump_payloads(&blocks);
    let window: Vec<&BlockPayload> = payloads.iter().collect();

    let outcomes = chain.apply_window(&window)?;

    assert_eq!(
        requested.load(Ordering::SeqCst),
        1,
        "the staged-tip hook runs once, inside the window's transition"
    );
    let handle = closer
        .lock()
        .take()
        .ok_or("the shutdown thread was spawned from the hook")?;
    handle.join().map_err(|_| "the shutdown thread panicked")?;
    assert_eq!(
        outcomes.len(),
        3,
        "a shutdown requested while the window runs cannot cut the window short"
    );
    assert_eq!(
        outcomes[2].hash,
        Hash256::from(blocks[2].block_hash()),
        "the whole window commits in order before the shutdown acquires the transition"
    );
    let applied = chain
        .applied_tip_snapshot()
        .ok_or("the window publishes a tip")?;
    assert_eq!(
        applied.hash,
        Hash256::from(blocks[2].block_hash()),
        "the published tip is the complete window, not a partial prefix"
    );
    assert!(
        chain.is_closed_for_recovery(),
        "the shutdown that waited for the window closes admission after it"
    );
    let refused = chain
        .apply_window(&window)
        .err()
        .ok_or("closed admission refuses a new window")?;
    assert!(
        matches!(refused.source, ApplyError::Shutdown),
        "a window after the shutdown is refused at admission, got {:?}",
        refused.source
    );
    Ok(())
}

// RCV-02
#[test]
fn a_window_crash_at_a_group_commit_boundary_keeps_the_last_complete_group() -> TestResult {
    let body_blocks = u32::try_from(GROUP_BLOCKS.saturating_add(1)).map_err(|_| "group size")?;
    let mut blocks = Vec::new();
    let mut parent = Network::Regtest.genesis_block().block_hash();
    for height in 1..=body_blocks {
        let block = mined_child(parent, height)?;
        parent = block.block_hash();
        blocks.push(block);
    }
    let payloads = dump_payloads(&blocks);

    for (fail_on_commit, committed_blocks) in [(2_u64, 0_usize), (3, GROUP_BLOCKS)] {
        let mut chain = handles(Network::Regtest, Arc::new(UtxoSet::new()));
        seed_genesis(&chain)?;
        let fault = Arc::new(CrashOnCommitHead::new(fail_on_commit));
        chain.durable_head = Arc::clone(&fault) as Arc<dyn DurableHeadStore>;
        commit_genesis_head(&chain)?;
        let refs: Vec<&Block> = blocks.iter().collect();
        apply_headers(&chain, &refs)?;
        let window: Vec<&BlockPayload> = payloads.iter().collect();

        let error = chain
            .apply_window(&window)
            .err()
            .ok_or("a failed durable head commit must abort the window")?;

        assert_eq!(
            error.disposition,
            WindowApplyDisposition::Fatal,
            "a failed durable head commit is unrecoverable without restart"
        );
        assert_eq!(
            error.applied, committed_blocks,
            "a crash on commit {fail_on_commit} leaves exactly the groups committed before it"
        );
        assert_eq!(
            error.committed.len(),
            committed_blocks,
            "only flushed groups count as committed after a crash on commit {fail_on_commit}"
        );
        let head = chain
            .durable_head
            .load()?
            .ok_or("the genesis head survives the crash")?;
        let applied = chain
            .applied_tip_snapshot()
            .ok_or("the pre-crash tip survives")?;
        let expected_hash = committed_blocks
            .checked_sub(1)
            .and_then(|index| blocks.get(index))
            .map_or_else(
                || Hash256::from(Network::Regtest.genesis_block().block_hash()),
                |block| Hash256::from(block.block_hash()),
            );
        let expected_height = u32::try_from(committed_blocks).unwrap_or(u32::MAX);
        assert_eq!(
            (head.height, head.tip),
            (expected_height, expected_hash),
            "the durable head after a crash on commit {fail_on_commit} names the last complete group"
        );
        assert_eq!(
            (applied.height, applied.hash),
            (expected_height, expected_hash),
            "the published tip after a crash on commit {fail_on_commit} agrees with the durable head"
        );
    }
    Ok(())
}
