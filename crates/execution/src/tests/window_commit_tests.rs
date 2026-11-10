use std::collections::HashMap;
use std::sync::Arc;

use crate::chain::regtest_fixture::{
    merkle_root, mine_block_to_declared_target, mined_block_with_prev_hash,
    mined_regtest_child_at as mined_child, mined_regtest_child_at_time as mined_child_at_time,
};
use bitcoin_rs_consensus::ConsensusError;
use bitcoin_rs_consensus::bip30::is_bip30_exception;
use bitcoin_rs_consensus::primitives::{
    Amount, Block, BlockImage, Hash256, LockTime, Network, OutPoint, Script, Sequence, Tx, TxIn,
    TxOut, Witness,
};
use bitcoin_rs_consensus::script::opcode::OP_PUSHNUM_1;
use bitcoin_rs_storage::coins::{CoinKey, CoinStore};
use bitcoin_rs_storage::commit::AcceptedPrefix;
use bitcoin_rs_storage::durable_head::DurableHead;
use bitcoin_rs_storage::utxo::UtxoSet;
use bitcoin_rs_storage::{ColumnFamily, WindowDelta};

use crate::ApplyError;
use crate::Chainstate;
use crate::test_fixtures::{
    Corpus, CorpusBlockPlan, CorpusSpend, CorpusSpendPlan, TestError, TestResult, coin_scan,
    handles, seed_genesis,
};
use proptest::prelude::*;

const OLDEST_SPENDABLE_COINBASE_HEIGHT: u32 = 1;

fn remine(block: &mut Block) -> TestResult {
    block.header.merkle_root = merkle_root(&block.txs).ok_or(TestError::Missing("merkle root"))?;
    mine_block_to_declared_target(block)?;
    Ok(())
}

fn dump_payloads(blocks: &[Block]) -> Vec<BlockImage> {
    blocks
        .iter()
        .map(|block| BlockImage::from_local(block.clone()))
        .collect()
}

fn apply_headers(chain: &Chainstate, blocks: &[&Block]) -> TestResult {
    let headers: Vec<_> = blocks.iter().map(|block| block.header).collect();
    chain.admit_headers(&headers)?;
    Ok(())
}

fn commit_genesis_head(chain: &Chainstate) -> TestResult {
    let genesis = Network::Regtest.genesis_block();
    let prefix = AcceptedPrefix {
        expected_head: None,
        next_head: DurableHead {
            assumeutxo: crate::AssumeUtxoDiskStatus::Uninitialized,
            commit_id: 1,
            height: 0,
            tip: Hash256::from(genesis.block_hash()),
            chain_tx_count: 1,
            body_extent: None,
            undo_extent: None,
        },
        undo_rows: Vec::new(),
        body_rows: Vec::new(),
        attestation: None,
        coin_delta: WindowDelta::default(),
    };
    chain
        .commit_authority
        .commit_prefix(prefix)
        .map_err(|e| match e {
            bitcoin_rs_storage::CommitError::Storage(s) => s,
            other => bitcoin_rs_storage::StorageError::backend(other.to_string()),
        })?;
    Ok(())
}

fn window_slices(len: usize, cuts: &[usize]) -> Vec<(usize, usize)> {
    let mut bounds: Vec<usize> = cuts
        .iter()
        .filter(|cut| **cut > 0 && **cut < len)
        .copied()
        .collect();
    bounds.sort_unstable();
    bounds.dedup();
    let mut slices = Vec::new();
    let mut start = 0;
    for end in bounds.into_iter().chain(std::iter::once(len)) {
        if end > start {
            slices.push((start, end));
            start = end;
        }
    }
    slices
}

fn generated_plan(shape: GeneratedShape) -> Vec<CorpusBlockPlan> {
    let first = CorpusBlockPlan {
        spends: vec![
            CorpusSpendPlan {
                spend: CorpusSpend::MatureCoinbase {
                    height: OLDEST_SPENDABLE_COINBASE_HEIGHT,
                },
            },
            CorpusSpendPlan {
                spend: CorpusSpend::SameBlock { tx: 0 },
            },
        ],
    };
    let second = CorpusBlockPlan {
        spends: vec![
            CorpusSpendPlan {
                spend: CorpusSpend::EarlierBlock { block: 0, tx: 1 },
            },
            CorpusSpendPlan {
                spend: CorpusSpend::SameBlock { tx: 0 },
            },
        ],
    };
    match shape {
        GeneratedShape::SameWindow => vec![first, second],
        GeneratedShape::CrossWindow => vec![first, second, CorpusBlockPlan::default()],
        GeneratedShape::Mixed => vec![
            first,
            CorpusBlockPlan::default(),
            second,
            CorpusBlockPlan {
                spends: vec![CorpusSpendPlan {
                    spend: CorpusSpend::EarlierBlock { block: 2, tx: 1 },
                }],
            },
        ],
    }
}

#[derive(Clone, Copy, Debug)]
enum GeneratedShape {
    SameWindow,
    CrossWindow,
    Mixed,
}

// WIN-03, RCV-04
proptest! {
    #![proptest_config(ProptestConfig {
        cases: std::env::var("PROPTEST_CASES")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(24),
        ..ProptestConfig::default()
    })]
    #[test]
    fn every_committed_prefix_equals_sequential_execution(
        shape in 0_u8..3,
        cut_a in 0_usize..5,
        cut_b in 0_usize..5,
    ) {
        let shape = match shape {
            0 => GeneratedShape::SameWindow,
            1 => GeneratedShape::CrossWindow,
            _ => GeneratedShape::Mixed,
        };
        run_corpus_prefix_equivalence(shape, &[cut_a, cut_b])
            .map_err(|error| TestCaseError::fail(format!("{error:?}")))?;
    }
}

fn run_corpus_prefix_equivalence(shape: GeneratedShape, cuts: &[usize]) -> TestResult {
    let corpus = Corpus::build(&generated_plan(shape))?;
    let payloads = corpus.payloads();

    let windowed = handles(Network::Regtest, Arc::new(UtxoSet::new()));
    seed_genesis(&windowed)?;
    commit_genesis_head(&windowed)?;
    let sequential = handles(Network::Regtest, Arc::new(UtxoSet::new()));
    seed_genesis(&sequential)?;
    commit_genesis_head(&sequential)?;

    for block in &corpus.prefix {
        let image = BlockImage::from_local(block.clone());
        windowed.apply_block(&image)?;
        sequential.apply_block(&image)?;
    }

    let block_refs: Vec<&Block> = corpus.blocks.iter().collect();
    apply_headers(&windowed, &block_refs)?;
    apply_headers(&sequential, &block_refs)?;

    let mut committed_prefix = 0;
    for (start, end) in window_slices(payloads.len(), cuts) {
        let window: Vec<&BlockImage> = payloads[start..end].iter().collect();
        let outcomes = windowed.apply_window(&window)?;
        assert_eq!(outcomes.len(), end - start);

        for payload in &payloads[start..end] {
            sequential.apply_block(payload)?;
            committed_prefix += 1;
        }

        let window_head = windowed
            .durable_head
            .load()?
            .ok_or(TestError::Missing("window durable head"))?;
        let oracle_head = sequential
            .durable_head
            .load()?
            .ok_or(TestError::Missing("oracle durable head"))?;
        assert_eq!(
            (
                window_head.height,
                window_head.tip,
                window_head.chain_tx_count
            ),
            (
                oracle_head.height,
                oracle_head.tip,
                oracle_head.chain_tx_count
            ),
            "durable head must match the sequential oracle at committed prefix {committed_prefix}"
        );
        assert_eq!(
            coin_scan(&windowed)?,
            coin_scan(&sequential)?,
            "engine coins must match the sequential oracle at committed prefix {committed_prefix}"
        );
    }
    Ok(())
}

// WIN-04
#[test]
fn create_and_spend_inside_prefix_never_reaches_coin_store() -> TestResult {
    let chain = handles(Network::Regtest, Arc::new(UtxoSet::new()));
    seed_genesis(&chain)?;
    commit_genesis_head(&chain)?;

    let mut parent = Network::Regtest.genesis_block().block_hash();
    let mut funding = None;
    for height in 1..=100_u32 {
        let block = mined_child(parent, height)?;
        if height == 1 {
            funding = Some(OutPoint::new(block.txs[0].txid(), 0));
        }
        chain.apply_block(&BlockImage::from_local(block.clone()))?;
        parent = block.block_hash();
    }
    let funding = funding.ok_or(TestError::Missing("funding coinbase"))?;

    let ephemeral_tx = Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: funding,
            script_sig: Script::from_bytes(vec![OP_PUSHNUM_1]),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(40_000),
            script_pubkey: Script::from_bytes(vec![OP_PUSHNUM_1]),
        }],
        lock_time: LockTime::ZERO,
    };
    let ephemeral_txid = ephemeral_tx.txid();
    let ephemeral_outpoint = OutPoint::new(ephemeral_txid, 0);

    let mut b101 = mined_child(parent, 101)?;
    b101.txs.push(ephemeral_tx);
    remine(&mut b101)?;

    let spend_tx = Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: ephemeral_outpoint,
            script_sig: Script::from_bytes(vec![OP_PUSHNUM_1]),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(30_000),
            script_pubkey: Script::from_bytes(vec![OP_PUSHNUM_1]),
        }],
        lock_time: LockTime::ZERO,
    };
    let mut b102 = mined_child(b101.block_hash(), 102)?;
    b102.txs.push(spend_tx);
    remine(&mut b102)?;

    let blocks = [b101, b102];
    let block_refs: Vec<&Block> = blocks.iter().collect();
    apply_headers(&chain, &block_refs)?;

    let payloads = dump_payloads(&blocks);
    let payload_refs: Vec<&BlockImage> = payloads.iter().collect();

    chain.apply_window(&payload_refs)?;

    let key = CoinKey(ephemeral_txid.0.to_le_bytes());
    let store = chain.commit_authority.store();
    let raw_entry = store.get(ColumnFamily::Coins, key.as_bytes())?;
    assert!(
        raw_entry.is_none(),
        "ephemeral coin record must never reach the persistent engine coin store"
    );

    Ok(())
}

// WIN-08
#[test]
fn failure_at_block_j_commits_prefix_before_j() -> TestResult {
    let chain = handles(Network::Regtest, Arc::new(UtxoSet::new()));
    seed_genesis(&chain)?;
    commit_genesis_head(&chain)?;

    let genesis = Network::Regtest.genesis_block();
    let b1 = mined_child(genesis.block_hash(), 1)?;
    let b2 = mined_child(b1.block_hash(), 2)?;
    let mut b3 = mined_child(b2.block_hash(), 3)?;
    b3.txs[0].outputs[0].value = Amount::from_sat(500_000_000_000);
    remine(&mut b3)?;

    apply_headers(&chain, &[&b1, &b2, &b3])?;

    let blocks = [b1.clone(), b2.clone(), b3.clone()];
    let payloads = dump_payloads(&blocks);
    let payload_refs: Vec<&BlockImage> = payloads.iter().collect();

    let result = chain.apply_window(&payload_refs);
    assert!(result.is_err(), "window with corrupt block 3 must fail");

    let head = chain
        .durable_head
        .load()?
        .ok_or(TestError::Missing("durable head must be committed"))?;
    assert_eq!(
        head.height, 2,
        "durable head must commit valid prefix up to height 2"
    );
    assert_eq!(head.tip, b2.block_hash().0);

    let b1_key = CoinKey(b1.txs[0].txid().0.to_le_bytes());
    let b2_key = CoinKey(b2.txs[0].txid().0.to_le_bytes());
    let b3_key = CoinKey(b3.txs[0].txid().0.to_le_bytes());
    assert!(chain.coins.get(&b1_key)?.is_some());
    assert!(chain.coins.get(&b2_key)?.is_some());
    assert!(chain.coins.get(&b3_key)?.is_none());

    Ok(())
}

// CMT-03
#[test]
fn crash_between_commit_and_cache_install_reloads_from_engine() -> TestResult {
    let chain = handles(Network::Regtest, Arc::new(UtxoSet::new()));
    seed_genesis(&chain)?;
    commit_genesis_head(&chain)?;

    let genesis = Network::Regtest.genesis_block();
    let b1 = mined_child(genesis.block_hash(), 1)?;
    apply_headers(&chain, &[&b1])?;

    let payload = BlockImage::from_local(b1.clone());
    chain.apply_window(&[&payload])?;

    let store = Arc::clone(chain.commit_authority.store());
    let fresh_coins = CoinStore::open(store, 64 * 1024 * 1024);
    let cb_txid = b1.txs[0].txid();
    let key = CoinKey(cb_txid.0.to_le_bytes());

    let reloaded = fresh_coins
        .get(&key)?
        .ok_or(TestError::Missing("coin must reload from engine"))?;
    assert_eq!(&reloaded[0..32], &cb_txid.0.to_le_bytes());

    Ok(())
}

// WIN-07
#[test]
fn bip30_overwrite_stays_explicit() -> TestResult {
    let genesis = Network::Regtest.genesis_block();
    let b1 = mined_child(genesis.block_hash(), 1)?;
    let b2 = mined_child(b1.block_hash(), 2)?;
    let mut duplicate = mined_child(b2.block_hash(), 3)?;
    duplicate.txs[0] = b1.txs[0].clone();
    remine(&mut duplicate)?;
    let blocks = [b1.clone(), b2.clone(), duplicate.clone()];

    let windowed = fresh_regtest_chain_with_bodies()?;
    let block_refs: Vec<&Block> = blocks.iter().collect();
    apply_headers(&windowed, &block_refs)?;
    let payloads = dump_payloads(&blocks);
    let payload_refs: Vec<&BlockImage> = payloads.iter().collect();
    let error = windowed
        .apply_window(&payload_refs)
        .err()
        .ok_or(TestError::UnexpectedSuccess(
            "a duplicate txid outside the BIP30 exceptions must fail the window",
        ))?;
    assert!(
        matches!(
            *error.source,
            ApplyError::Consensus(ConsensusError::Bip { .. })
        ),
        "the duplicate must be refused by the BIP30 rule, got {:?}",
        error.source
    );
    assert!(
        !is_bip30_exception(3, Hash256::from(duplicate.block_hash())),
        "regtest height 3 is not a BIP30 exception height"
    );

    let committed = windowed.durable_head.load()?.map_or(0, |head| head.height);
    let sequential = fresh_regtest_chain_with_bodies()?;
    for block in blocks.iter().take(usize::try_from(committed)?) {
        sequential.apply_block(&BlockImage::from_local(block.clone()))?;
    }
    assert_chain_matches_oracle(
        &windowed,
        &sequential,
        "for the prefix before the duplicate",
    )
}

fn fresh_regtest_chain_with_bodies() -> TestResult<Chainstate> {
    let mut chain = handles(Network::Regtest, Arc::new(UtxoSet::new()));
    chain.block_body_store = Some(Arc::new(crate::test_support::MemoryBodies::default()));
    seed_genesis(&chain)?;
    commit_genesis_head(&chain)?;
    Ok(chain)
}

fn winning_plan() -> Vec<CorpusBlockPlan> {
    vec![
        CorpusBlockPlan {
            spends: vec![CorpusSpendPlan {
                spend: CorpusSpend::MatureCoinbase {
                    height: OLDEST_SPENDABLE_COINBASE_HEIGHT,
                },
            }],
        },
        CorpusBlockPlan {
            spends: vec![
                CorpusSpendPlan {
                    spend: CorpusSpend::EarlierBlock { block: 0, tx: 0 },
                },
                CorpusSpendPlan {
                    spend: CorpusSpend::SameBlock { tx: 0 },
                },
            ],
        },
        CorpusBlockPlan {
            spends: vec![CorpusSpendPlan {
                spend: CorpusSpend::EarlierBlock { block: 1, tx: 1 },
            }],
        },
    ]
}

struct NoopReorgObserver;

impl crate::reorg::ReorgObserver for NoopReorgObserver {
    fn disconnected(&mut self, _: &crate::DisconnectOutcome) {}

    fn connected(&mut self, _: &BlockImage, _: &crate::ConnectOutcome) {}

    fn reconsider_disconnected(&mut self, _: &BlockImage) {}
}

fn assert_chain_matches_oracle(
    windowed: &Chainstate,
    sequential: &Chainstate,
    stage: &str,
) -> TestResult {
    let window_head = windowed
        .durable_head
        .load()?
        .ok_or(TestError::Missing("window durable head"))?;
    let oracle_head = sequential
        .durable_head
        .load()?
        .ok_or(TestError::Missing("oracle durable head"))?;
    assert_eq!(
        (
            window_head.height,
            window_head.tip,
            window_head.chain_tx_count
        ),
        (
            oracle_head.height,
            oracle_head.tip,
            oracle_head.chain_tx_count
        ),
        "durable head must match the sequential oracle {stage}"
    );
    assert_eq!(
        coin_scan(windowed)?,
        coin_scan(sequential)?,
        "engine coins must match the sequential oracle {stage}"
    );
    Ok(())
}

// REO-02, REO-03
#[test]
fn reorg_inside_committed_window_equals_winning_branch() -> TestResult {
    let losing = Corpus::build(&generated_plan(GeneratedShape::SameWindow))?;
    let winning = Corpus::build(&winning_plan())?;

    let windowed = fresh_regtest_chain_with_bodies()?;
    for block in &losing.prefix {
        windowed.apply_block(&BlockImage::from_local(block.clone()))?;
    }
    let losing_refs: Vec<&Block> = losing.blocks.iter().collect();
    apply_headers(&windowed, &losing_refs)?;
    let losing_payloads = losing.payloads();
    let losing_window: Vec<&BlockImage> = losing_payloads.iter().collect();
    windowed.apply_window(&losing_window)?;
    let committed_loser = windowed
        .durable_head
        .load()?
        .ok_or(TestError::Missing("losing window must commit a head"))?;
    let expected_height = u32::try_from(losing.prefix.len() + losing.blocks.len())?;
    assert_eq!(
        committed_loser.height, expected_height,
        "both losing blocks must sit inside one committed window"
    );

    let winning_refs: Vec<&Block> = winning.blocks.iter().collect();
    apply_headers(&windowed, &winning_refs)?;
    let winning_payloads = winning.payloads();
    let bodies: HashMap<Hash256, BlockImage> = winning
        .blocks
        .iter()
        .zip(&winning_payloads)
        .map(|(block, payload)| (Hash256::from(block.block_hash()), payload.clone()))
        .collect();
    let winning_tip = winning
        .blocks
        .last()
        .ok_or(TestError::Missing("winning branch has blocks"))?
        .block_hash();
    let target = windowed
        .block_tree
        .read()
        .lookup(Hash256::from(winning_tip))
        .ok_or(TestError::Missing("winning tip header"))?;
    crate::reorg::switch_to_branch(
        &windowed,
        target,
        |hash| bodies.get(&hash).cloned(),
        &mut NoopReorgObserver,
        |_, outcome| outcome,
    )?;
    let reorged = windowed
        .applied_tip_snapshot()
        .ok_or(TestError::Missing("reorg publishes a tip"))?;
    assert_eq!(
        reorged.hash,
        Hash256::from(winning_tip),
        "the reorg moves the applied tip onto the winning branch"
    );

    let sequential = fresh_regtest_chain_with_bodies()?;
    for block in &losing.prefix {
        sequential.apply_block(&BlockImage::from_local(block.clone()))?;
    }
    apply_headers(&sequential, &winning_refs)?;
    for payload in &winning_payloads {
        sequential.apply_block(payload)?;
    }

    assert_chain_matches_oracle(&windowed, &sequential, "after the reorg")
}

// WIN-06, WIN-08
#[test]
fn unlinked_window_block_commits_only_prefix_with_matching_coins() -> TestResult {
    let genesis = Network::Regtest.genesis_block();
    let linked = mined_child(genesis.block_hash(), 1)?;
    let unlinked = mined_child_at_time(genesis.block_hash(), genesis.header.time + 5, 1)?;
    let blocks = [linked.clone(), unlinked.clone()];
    let windowed = fresh_regtest_chain_with_bodies()?;
    let block_refs: Vec<&Block> = blocks.iter().collect();
    apply_headers(&windowed, &block_refs)?;
    let payloads = dump_payloads(&blocks);
    let payload_refs: Vec<&BlockImage> = payloads.iter().collect();
    assert!(
        windowed.apply_window(&payload_refs).is_err(),
        "a block that does not extend its predecessor must fail the window"
    );

    let committed = windowed.durable_head.load()?.map_or(0, |head| head.height);
    assert_eq!(
        committed, 1,
        "the linked block must commit before the unlinked block fails the window"
    );
    let linked_key = CoinKey(linked.txs[0].txid().0.to_le_bytes());
    assert!(
        coin_scan(&windowed)?
            .iter()
            .any(|(key, _)| key.as_slice() == linked_key.as_bytes()),
        "the linked coinbase must be live in the engine coin keyspace"
    );
    let sequential = fresh_regtest_chain_with_bodies()?;
    for block in blocks.iter().take(usize::try_from(committed)?) {
        sequential.apply_block(&BlockImage::from_local(block.clone()))?;
    }
    assert_chain_matches_oracle(
        &windowed,
        &sequential,
        "for the committed prefix of a failed window",
    )
}
// WIN-03, RCV-04
#[test]
fn fixed_window_committed_prefix_equals_sequential_execution() -> TestResult {
    let chain1 = handles(Network::Regtest, Arc::new(UtxoSet::new()));
    seed_genesis(&chain1)?;
    commit_genesis_head(&chain1)?;

    let chain2 = handles(Network::Regtest, Arc::new(UtxoSet::new()));
    seed_genesis(&chain2)?;
    commit_genesis_head(&chain2)?;

    let genesis = Network::Regtest.genesis_block();
    let b1 = mined_child(genesis.block_hash(), 1)?;
    let b2 = mined_child(b1.block_hash(), 2)?;
    let b3 = mined_child(b2.block_hash(), 3)?;
    let blocks = [b1, b2, b3];
    let block_refs: Vec<&Block> = blocks.iter().collect();

    apply_headers(&chain1, &block_refs)?;
    apply_headers(&chain2, &block_refs)?;

    let payloads = dump_payloads(&blocks);
    let payload_refs: Vec<&BlockImage> = payloads.iter().collect();

    let window_outcomes = chain1.apply_window(&payload_refs)?;
    assert_eq!(window_outcomes.len(), 3);

    for payload in &payloads {
        let single = chain2.apply_window(&[payload])?;
        assert_eq!(single.len(), 1);
    }

    let head1 = chain1
        .durable_head
        .load()?
        .ok_or(TestError::Missing("durable head 1"))?;
    let head2 = chain2
        .durable_head
        .load()?
        .ok_or(TestError::Missing("durable head 2"))?;
    assert_eq!(head1.height, head2.height);
    assert_eq!(head1.tip, head2.tip);
    assert_eq!(head1.chain_tx_count, head2.chain_tx_count);

    for block in &blocks {
        let cb_txid = block.txs[0].txid();
        let key = CoinKey(cb_txid.0.to_le_bytes());
        let coin1 = chain1.coins.get(&key)?;
        let coin2 = chain2.coins.get(&key)?;
        assert_eq!(coin1, coin2, "coin state must match for {cb_txid}");
        assert!(coin1.is_some(), "coinbase output must exist");
    }

    Ok(())
}
// WIN-07
#[test]
fn window_rejects_duplicate_txid_staged_in_the_same_window() -> TestResult {
    let chain = handles(Network::Regtest, Arc::new(UtxoSet::new()));
    seed_genesis(&chain)?;
    commit_genesis_head(&chain)?;

    let genesis = Network::Regtest.genesis_block();
    let b1 = mined_child(genesis.block_hash(), 1)?;
    let b1_hash = b1.block_hash().0;
    let b2 = mined_block_with_prev_hash(b1.block_hash(), 2, vec![b1.txs[0].clone()])?;
    assert_eq!(b1.txs[0].txid(), b2.txs[0].txid());

    apply_headers(&chain, &[&b1, &b2])?;
    let blocks = [b1, b2];
    let payloads = dump_payloads(&blocks);
    let payload_refs: Vec<&BlockImage> = payloads.iter().collect();

    let error = match chain.apply_window(&payload_refs) {
        Ok(outcomes) => panic!(
            "duplicate coinbase txid staged in one commit window was accepted; \
             head at height {}",
            outcomes.last().map_or(0, |outcome| outcome.height)
        ),
        Err(error) => error,
    };
    assert!(
        error.to_string().contains("BIP30"),
        "the rejection must name BIP30, got: {error}"
    );

    let head = chain
        .durable_head
        .load()?
        .ok_or(TestError::Missing("durable head"))?;
    assert_eq!(
        head.height, 1,
        "the valid prefix before the rejected block commits and the rejected block does not"
    );
    assert_eq!(head.tip, b1_hash);

    Ok(())
}

fn insert_engine_coin(
    chain: &Chainstate,
    txid: bitcoin_rs_consensus::primitives::Txid,
) -> TestResult {
    let record = bitcoin_rs_storage::utxo::record::UtxoRecord::from_owned_outputs(
        txid.0,
        &[bitcoin_rs_storage::utxo::record::OwnedUtxoOut {
            vout: 0,
            value: 50_000,
            script_pubkey: vec![OP_PUSHNUM_1],
            coinbase: false,
            height: 0,
        }],
    )
    .map_err(|_| TestError::Missing("synthetic coin record"))?;
    chain.commit_authority.store().put(
        ColumnFamily::Coins,
        CoinKey(txid.0.to_le_bytes()).as_bytes(),
        record.bytes(),
    )?;
    Ok(())
}

// WIN-07
#[test]
fn engine_coin_spent_inside_the_window_is_not_a_duplicate() -> TestResult {
    let chain = handles(Network::Regtest, Arc::new(UtxoSet::new()));
    seed_genesis(&chain)?;
    commit_genesis_head(&chain)?;

    let genesis = Network::Regtest.genesis_block();
    let duplicate_tx = Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(genesis.txs[0].txid(), 0),
            script_sig: Script::from_bytes(vec![OP_PUSHNUM_1]),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: Script::from_bytes(vec![OP_PUSHNUM_1]),
        }],
        lock_time: LockTime::ZERO,
    };
    let duplicate_txid = duplicate_tx.txid();
    insert_engine_coin(&chain, duplicate_txid)?;

    let spend_tx = Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(duplicate_txid, 0),
            script_sig: Script::from_bytes(vec![OP_PUSHNUM_1]),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(40_000),
            script_pubkey: Script::from_bytes(vec![OP_PUSHNUM_1]),
        }],
        lock_time: LockTime::ZERO,
    };

    let mut b1 = mined_child(genesis.block_hash(), 1)?;
    b1.txs.push(spend_tx);
    remine(&mut b1)?;
    let b1_hash = b1.block_hash().0;
    let mut b2 = mined_child(b1.block_hash(), 2)?;
    b2.txs.push(duplicate_tx);
    remine(&mut b2)?;

    apply_headers(&chain, &[&b1, &b2])?;
    let blocks = [b1, b2];
    let payloads = dump_payloads(&blocks);
    let payload_refs: Vec<&BlockImage> = payloads.iter().collect();

    let error = match chain.apply_window(&payload_refs) {
        Ok(outcomes) => panic!(
            "a coin spent inside the window was reported as a duplicate; head at height {}",
            outcomes.last().map_or(0, |outcome| outcome.height)
        ),
        Err(error) => error,
    };
    assert!(
        !error.to_string().contains("BIP30"),
        "a coin spent inside the window is not a duplicate, got: {error}"
    );
    assert!(
        error.to_string().contains("missing prevout"),
        "block 2 must fail on its absent prevout, got: {error}"
    );

    let head = chain
        .durable_head
        .load()?
        .ok_or(TestError::Missing("durable head"))?;
    assert_eq!(head.height, 1);
    assert_eq!(head.tip, b1_hash);

    Ok(())
}

#[test]
fn engine_coin_duplicate_across_windows_is_rejected_by_bip30() -> TestResult {
    let chain = handles(Network::Regtest, Arc::new(UtxoSet::new()));
    seed_genesis(&chain)?;
    commit_genesis_head(&chain)?;

    let genesis = Network::Regtest.genesis_block();
    let b1 = mined_child(genesis.block_hash(), 1)?;
    let b1_hash = b1.block_hash().0;
    let b2 = mined_child(b1.block_hash(), 2)?;
    insert_engine_coin(&chain, b2.txs[0].txid())?;

    apply_headers(&chain, &[&b1, &b2])?;
    let blocks = [b1, b2];
    let payloads = dump_payloads(&blocks);
    let payload_refs: Vec<&BlockImage> = payloads.iter().collect();

    let error = match chain.apply_window(&payload_refs) {
        Ok(outcomes) => panic!(
            "a coinbase already resident in the engine was accepted as new; head at height {}",
            outcomes.last().map_or(0, |outcome| outcome.height)
        ),
        Err(error) => error,
    };
    assert!(
        error.to_string().contains("BIP30"),
        "the rejection must name BIP30, got: {error}"
    );

    let head = chain
        .durable_head
        .load()?
        .ok_or(TestError::Missing("durable head"))?;
    assert_eq!(
        head.height, 1,
        "block 1 commits and the duplicate block does not"
    );
    assert_eq!(head.tip, b1_hash);

    Ok(())
}

// WIN-07
#[test]
fn gap_replay_token_keeps_the_duplicate_exemption() -> TestResult {
    let chain = handles(Network::Regtest, Arc::new(UtxoSet::new()));
    seed_genesis(&chain)?;
    commit_genesis_head(&chain)?;

    let genesis = Network::Regtest.genesis_block();
    let b1 = mined_child(genesis.block_hash(), 1)?;
    apply_headers(&chain, &[&b1])?;
    let b1_payload = BlockImage::from_local(b1.clone());
    chain.apply_window(&[&b1_payload])?;

    let b2 = mined_block_with_prev_hash(b1.block_hash(), 2, vec![b1.txs[0].clone()])?;
    assert_eq!(b1.txs[0].txid(), b2.txs[0].txid());
    apply_headers(&chain, &[&b2])?;
    let b2_payload = BlockImage::from_local(b2);

    let mut group = crate::window::WindowGroup::default();
    let outcome = crate::connect::apply_block_admitted(
        &chain,
        &b2_payload,
        None,
        crate::connect::ApplyScope {
            provenance: crate::BlockProvenance::LocalReplay(crate::durable::replay_token_for_test()),
            staged: None,
        },
        crate::ApplyIntent::Commit,
        crate::window::PublishMode::Grouped(&mut group),
    );
    assert!(
        outcome.is_ok(),
        "the durable gap replay keeps its duplicate exemption"
    );
    Ok(())
}

// WIN-05
#[test]
fn corrupt_engine_coin_record_fails_closed() -> TestResult {
    let chain = handles(Network::Regtest, Arc::new(UtxoSet::new()));
    seed_genesis(&chain)?;
    commit_genesis_head(&chain)?;

    let genesis = Network::Regtest.genesis_block();
    let owner_tx = Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(genesis.txs[0].txid(), 0),
            script_sig: Script::from_bytes(vec![OP_PUSHNUM_1]),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: Script::from_bytes(vec![OP_PUSHNUM_1]),
        }],
        lock_time: LockTime::ZERO,
    };
    let coin_txid = owner_tx.txid();
    chain.commit_authority.store().put(
        ColumnFamily::Coins,
        CoinKey(coin_txid.0.to_le_bytes()).as_bytes(),
        &[0xff; 5],
    )?;

    let spend_tx = Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(coin_txid, 0),
            script_sig: Script::from_bytes(vec![OP_PUSHNUM_1]),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(40_000),
            script_pubkey: Script::from_bytes(vec![OP_PUSHNUM_1]),
        }],
        lock_time: LockTime::ZERO,
    };
    let mut block = mined_child(genesis.block_hash(), 1)?;
    block.txs.push(spend_tx);
    remine(&mut block)?;
    apply_headers(&chain, &[&block])?;
    let payload = BlockImage::from_local(block);

    let Err(error) = chain.apply_window(&[&payload]) else {
        return Err(TestError::UnexpectedSuccess(
            "a corrupt coin record must refuse the window",
        ));
    };
    assert!(
        matches!(
            error.source.as_ref(),
            crate::ApplyError::UtxoCommit(bitcoin_rs_storage::utxo::set::UtxoError::CorruptRecord)
        ),
        "expected a typed corrupt-record error, got: {error}"
    );
    assert_eq!(error.disposition, crate::WindowApplyDisposition::Fatal);

    let head = chain
        .durable_head
        .load()?
        .ok_or(TestError::Missing("durable head"))?;
    assert_eq!(
        head.height, 0,
        "the refused window must not advance the head"
    );
    Ok(())
}
