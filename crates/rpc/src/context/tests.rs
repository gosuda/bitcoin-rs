use super::*;

struct ReadySource;

impl bitcoin_rs_index::DerivedIndexCapabilitySource for ReadySource {
    fn capability(&self) -> bitcoin_rs_index::CapabilityStatus {
        bitcoin_rs_index::derived_index_status(true, bitcoin_rs_index::CapabilityState::Ready)
    }
}

#[test]
fn eight_threads_share_one_context_for_getblockcount() {
    use alloc::vec::Vec;
    use sonic_rs::json;

    use crate::handlers::Handler;

    let handler = Arc::new(Handler::new(Arc::new(Context::new())));
    let workers: Vec<std::thread::JoinHandle<_>> = (0..8)
        .map(|_| {
            let handler = Arc::clone(&handler);
            std::thread::spawn(move || handler.dispatch("getblockcount", &json!([])))
        })
        .collect();
    for worker in workers {
        let outcome = worker.join().expect("a worker answers");
        assert!(
            outcome.is_ok(),
            "shared dispatch must answer every worker: {outcome:?}"
        );
    }
}

#[test]
fn applied_tip_publication_carries_the_transaction_count() {
    let ctx = Context::new();
    let counted = |count| {
        Arc::new(TipSnapshot {
            tip_id: bitcoin_rs_chain::NodeId::new(0),
            height: 0,
            chainwork: bitcoin_rs_chain::ChainWork::ZERO,
            hash: bitcoin_rs_primitives::Hash256::default(),
            chain_tx_count: bitcoin_rs_chain::ChainTxCount::established(count),
        })
    };
    ctx.chain.applied_tip.store(Some(counted(1)));
    assert_eq!(ctx.chain.applied_view().chain_tx_count(), Some(1));
    ctx.chain.applied_tip.store(Some(counted(42)));
    assert_eq!(ctx.chain.applied_view().chain_tx_count(), Some(42));
}

#[test]
fn applied_view_uses_one_publication() {
    use bitcoin_rs_chain::{ChainTxCount, ChainWork, NodeId};

    let ctx = Context::new();
    let tip = |height: u32, byte: u8, work: u64, count| {
        Arc::new(TipSnapshot {
            tip_id: NodeId::new(height),
            height,
            chainwork: ChainWork::from(work),
            hash: Hash256::from_le_bytes(&[byte; 32]),
            chain_tx_count: count,
        })
    };

    let empty = ctx.chain.applied_view();
    assert_eq!(empty.tip(), None);
    assert_eq!(empty.height(), 0);
    assert_eq!(
        empty.hash(Network::Mainnet),
        Network::Mainnet.genesis_block_hash()
    );
    assert_eq!(empty.chain_tx_count(), None);

    let a = tip(10, 0xaa, 7, ChainTxCount::established(100));
    let b = tip(20, 0xbb, 9, ChainTxCount::established(200));
    ctx.chain.applied_tip.store(Some(Arc::clone(&a)));
    let view = ctx.chain.applied_view();
    ctx.chain.applied_tip.store(Some(b));

    assert_eq!(view.height(), 10, "height must stay at the capture");
    assert_eq!(
        view.hash(Network::Mainnet),
        Hash256::from_le_bytes(&[0xaa_u8; 32]),
        "hash must stay at the capture"
    );
    assert_eq!(
        view.tip().map(|tip| tip.chainwork),
        Some(ChainWork::from(7_u64)),
        "work must stay at the capture"
    );
    assert_eq!(view.chain_tx_count(), Some(100), "count must stay");

    assert_eq!(ctx.chain.applied_view().height(), 20);

    ctx.chain
        .applied_tip
        .store(Some(tip(30, 0xcc, 11, ChainTxCount::UNKNOWN)));
    let unknown = ctx.chain.applied_view();
    assert_eq!(unknown.height(), 30);
    assert_eq!(unknown.chain_tx_count(), None);
}

#[test]
fn applied_view_does_not_wait_for_transition() -> anyhow::Result<()> {
    use std::sync::mpsc;
    use std::time::Duration;

    let barrier = bitcoin_rs_chain::TransitionDomain::new().stable_read();
    let ctx = Arc::new(Context::new().with_chain_transition(barrier.clone()));
    ctx.chain.applied_tip.store(Some(Arc::new(TipSnapshot {
        tip_id: bitcoin_rs_chain::NodeId::new(0),
        height: 5,
        chainwork: bitcoin_rs_chain::ChainWork::ZERO,
        hash: bitcoin_rs_primitives::Hash256::default(),
        chain_tx_count: bitcoin_rs_chain::ChainTxCount::established(1),
    })));

    let transition = barrier.lock();
    let worker = Arc::clone(&ctx);
    let (tx, rx) = mpsc::channel();
    let join = std::thread::spawn(move || {
        let _sent = tx.send(worker.chain.applied_view().height());
    });
    let height = rx
        .recv_timeout(Duration::from_secs(1))
        .map_err(|_| anyhow::anyhow!("capture blocked behind the transition barrier"))?;
    assert_eq!(height, 5, "the capture must see the published tip");
    join.join()
        .map_err(|_| anyhow::anyhow!("capture worker panicked"))?;
    drop(transition);
    Ok(())
}

fn shaped_records() -> Vec<BlockRecord> {
    const HEIGHTS: [u32; 8] = [1, 2, 3, 3, 3, 4, 8, 9];
    HEIGHTS
        .into_iter()
        .enumerate()
        .map(|(index, height)| {
            let mut hash = [0_u8; 32];
            hash[0] = u8::try_from(index).unwrap_or(0);
            let mut record =
                BlockRecord::synthetic(height, BlockHash::from(Hash256::from_le_bytes(&hash)));
            record.time = 1_000 + u32::try_from(index).unwrap_or(0);
            record
        })
        .collect()
}

#[test]
fn every_record_at_a_duplicated_height_is_reachable() {
    let records = shaped_records();
    let duplicates = records
        .iter()
        .filter(|record| record.height == 3)
        .map(|record| (record.hash, record.time))
        .collect::<Vec<_>>();
    assert_eq!(duplicates.len(), 3, "the fixture must duplicate height 3");

    for (hash, time) in duplicates {
        assert_eq!(
            record_at_height_hash(&records, 3, Hash256::from(hash)).map(|r| r.time),
            Some(time),
            "a record at a duplicated height was not reachable by its hash"
        );
    }
}

#[test]
fn block_by_height_without_an_applied_tip_reads_the_log() {
    let ctx = Context::new();
    for record in shaped_records() {
        ctx.chain.add_block(record);
    }

    for height in 0_u32..12 {
        let expected = shaped_records()
            .into_iter()
            .find(|candidate| candidate.height == height)
            .map(|record| record.hash);
        assert_eq!(
            ctx.chain.block_by_height(height).map(|record| record.hash),
            expected,
            "block_by_height disagrees with the log at height {height}"
        );
    }
}

#[test]
fn record_at_height_hash_picks_the_matching_hash_within_a_duplicate_height() {
    let first = Hash256::from_le_bytes(&[0x11_u8; 32]);
    let second = Hash256::from_le_bytes(&[0x22_u8; 32]);
    let records = vec![
        BlockRecord::synthetic(0, BlockHash::from(Hash256::from_le_bytes(&[0x00_u8; 32]))),
        BlockRecord::synthetic(1, BlockHash::from(first)),
        BlockRecord::synthetic(1, BlockHash::from(second)),
        BlockRecord::synthetic(2, BlockHash::from(Hash256::from_le_bytes(&[0x33_u8; 32]))),
    ];

    assert_eq!(
        record_at_height_hash(&records, 1, second).map(|record| Hash256::from(record.hash)),
        Some(second),
        "the second record at the height must be reachable, not just the first"
    );
    assert_eq!(
        record_at_height_hash(&records, 1, first).map(|record| Hash256::from(record.hash)),
        Some(first)
    );
    assert!(
        record_at_height_hash(&records, 1, Hash256::from_le_bytes(&[0x99_u8; 32])).is_none(),
        "a hash absent from the height run must not resolve to a sibling"
    );
}

#[test]
fn record_at_height_returns_the_first_record_of_a_duplicate_height() {
    let first = Hash256::from_le_bytes(&[0x11_u8; 32]);
    let records = vec![
        BlockRecord::synthetic(1, BlockHash::from(first)),
        BlockRecord::synthetic(1, BlockHash::from(Hash256::from_le_bytes(&[0x22_u8; 32]))),
        BlockRecord::synthetic(2, BlockHash::from(Hash256::from_le_bytes(&[0x33_u8; 32]))),
    ];

    assert_eq!(
        record_at_height(&records, 1).map(|record| Hash256::from(record.hash)),
        Some(first),
        "the dense index lands on the second duplicate; the first must win"
    );
    assert!(record_at_height(&records, 7).is_none());
}

#[test]
fn record_at_height_does_not_trust_the_index_on_a_sparse_log() {
    let wanted = Hash256::from_le_bytes(&[0x44_u8; 32]);
    let records = vec![
        BlockRecord::synthetic(10, BlockHash::from(Hash256::from_le_bytes(&[0x0a_u8; 32]))),
        BlockRecord::synthetic(11, BlockHash::from(wanted)),
        BlockRecord::synthetic(12, BlockHash::from(Hash256::from_le_bytes(&[0x0c_u8; 32]))),
    ];

    assert_eq!(
        record_at_height(&records, 11).map(|record| Hash256::from(record.hash)),
        Some(wanted),
        "a log that does not start at zero must still resolve by search"
    );
    assert!(record_at_height(&records, 1).is_none());
}

#[test]
#[expect(clippy::too_many_lines)]
fn from_handles_shares_chain_handles_with_caller() {
    use alloc::sync::Arc;

    let chain_tip = Arc::new(ArcSwapOption::empty());
    let applied_tip = Arc::new(ArcSwapOption::empty());
    let utxo = Arc::new(bitcoin_rs_utxo::UtxoSet::new());
    let coin_stats = Arc::new(bitcoin_rs_utxo::stats::CoinStatsListener::new(
        bitcoin_rs_utxo::stats::CoinStats::default(),
    ));
    let block_tree = Arc::new(RwLock::new(bitcoin_rs_chain::BlockTree::new()));
    let progress = bitcoin_rs_chain::ChainProgressReader::new(
        TipReader::new(Arc::clone(&chain_tip)),
        TipReader::new(Arc::clone(&applied_tip)),
        BlockTreeReader::new(Arc::clone(&block_tree)),
        Arc::new(bitcoin_rs_chain::InitialBlockDownload::new(
            TipReader::new(Arc::clone(&applied_tip)),
            BlockTreeReader::new(Arc::clone(&block_tree)),
        )),
    );
    let p2p = Arc::new(bitcoin_rs_p2p::P2pService::new(
        bitcoin_rs_p2p::P2pServiceConfig::default(),
        LatchReader::fixture_never(),
    ));
    let chain_transition = bitcoin_rs_chain::TransitionDomain::new().stable_read();
    let ctx = Context::from_handles(ContextHandles {
        chain: ChainHandles {
            chain_tip: TipReader::new(Arc::clone(&chain_tip)),
            applied_tip: TipReader::new(Arc::clone(&applied_tip)),
            active_tip_wait: None,
            progress,
            blocks: BlockLogReader::fixture_empty(),
            utxo: bitcoin_rs_utxo::UtxoReader::new(Arc::clone(&utxo)),
            coin_stats: Arc::clone(&coin_stats),
            block_tree: BlockTreeReader::new(Arc::clone(&block_tree)),
            chain_network: Network::Mainnet,
            chain_transition: chain_transition.clone(),
            ..ChainHandles::default()
        },
        mempool: MempoolHandles {
            gateway: Arc::new(MempoolGateway::new(
                Arc::new(RwLock::new(Mempool::new(MempoolLimits::default()))),
                None,
                ValidationEngine::Native,
                None,
            )),
        },
        network: NetworkHandles {
            peer_table: p2p.table(),
            p2p: Arc::clone(&p2p),
            local_services: 0x09,
            overlay: bitcoin_rs_p2p::overlay::OverlayConfig::default(),
        },
        ..ContextHandles::default()
    });
    let held = ctx.chain.chain_transition.lock();
    assert!(
        chain_transition.try_lock().is_none(),
        "the caller's role must exclude the same transitions the context does"
    );
    drop(held);
    let snapshot = |count| {
        Arc::new(TipSnapshot {
            tip_id: bitcoin_rs_chain::NodeId::new(0),
            height: 7,
            chainwork: bitcoin_rs_chain::ChainWork::ZERO,
            hash: Hash256::from_le_bytes(&[7; 32]),
            chain_tx_count: bitcoin_rs_chain::ChainTxCount::established(count),
        })
    };
    chain_tip.store(Some(snapshot(1)));
    assert_eq!(
        ctx.chain.chain_tip.load_full().map(|tip| tip.height),
        Some(7),
        "chain_tip must be shared with caller"
    );
    applied_tip.store(Some(snapshot(1)));
    assert_eq!(
        ctx.chain.applied_tip.load_full().map(|tip| tip.height),
        Some(7),
        "applied_tip must be shared with caller"
    );
    assert_eq!(ctx.chain.applied_view().chain_tx_count(), Some(1));
    applied_tip.store(Some(snapshot(42)));
    assert_eq!(ctx.chain.applied_view().chain_tx_count(), Some(42));
    let progress = ctx.chain.progress.progress(Network::Mainnet, 0);
    assert_eq!(
        (progress.blocks, progress.headers),
        (7, 7),
        "progress must read the caller's tips"
    );
    assert!(
        Arc::ptr_eq(&ctx.chain.utxo.fixture_set(), &utxo),
        "utxo must be shared with caller"
    );
    assert!(
        Arc::ptr_eq(&ctx.chain.coin_stats, &coin_stats),
        "coin_stats must be shared with caller"
    );
    {
        let genesis = Network::Regtest.genesis_block();
        let genesis_id = block_tree
            .write()
            .insert_node(
                None,
                genesis.header,
                bitcoin_rs_chain::node::NodeStatus::Active,
            )
            .expect("genesis insert");
        assert!(
            ctx.chain.block_tree.read().node(genesis_id).is_ok(),
            "block_tree must be shared with caller"
        );
    }
    assert!(
        Arc::ptr_eq(&ctx.network.p2p, &p2p),
        "p2p service must be shared with caller"
    );
}

#[test]
fn status_keeps_the_captured_applied_pair() {
    let ctx = Context::new();
    let tip = |height: u32, byte: u8, work: u64, count| {
        Arc::new(TipSnapshot {
            tip_id: bitcoin_rs_chain::NodeId::new(height),
            height,
            chainwork: bitcoin_rs_chain::ChainWork::from(work),
            hash: Hash256::from_le_bytes(&[byte; 32]),
            chain_tx_count: bitcoin_rs_chain::ChainTxCount::established(count),
        })
    };
    ctx.chain.applied_tip.store(Some(tip(3, 0xaa, 7, 42)));
    let captured = ctx.chain.applied_view();

    ctx.chain.applied_tip.store(Some(tip(9, 0xbb, 9, 84)));

    let progress = ctx.chain.sync_progress_at(&captured);
    assert_eq!(progress.blocks, 3, "blocks must stay at the capture");
    assert_eq!(
        progress.best_block_hash,
        Hash256::from_le_bytes(&[0xaa_u8; 32]),
        "the applied hash must stay at the capture"
    );
    assert_eq!(
        progress.chain_work,
        format!("{:064x}", bitcoin_rs_chain::ChainWork::from(7_u64)),
        "chainwork must stay at the capture"
    );
    assert_eq!(
        captured.chain_tx_count(),
        Some(42),
        "the captured count must stay paired with the captured tip"
    );

    assert_eq!(ctx.chain.sync_progress().blocks, 9);
}

#[test]
fn block_render_budget_releases_dropped_permits() {
    let ctx = Context::new();
    let first = ctx.try_acquire_block_render().expect("first permit");
    let second = ctx.try_acquire_block_render().expect("second permit");
    assert!(ctx.try_acquire_block_render().is_none());
    drop(first);
    assert!(ctx.try_acquire_block_render().is_some());
    drop(second);
}

#[test]
fn new_context_wires_utxo_commits_to_coin_stats() {
    use bitcoin_rs_primitives::{Hash256, OutPoint, TxOut, Txid};
    use bitcoin_rs_utxo::contract::{BlockChanges, UtxoAdd};

    let ctx = Context::new();
    let outpoint = OutPoint::new(Txid(Hash256::from_le_bytes(&[1_u8; 32])), 0);
    let txout = TxOut {
        value: Amount::from_sat(125_000),
        script_pubkey: Script::new(),
    };
    let mut changes = BlockChanges::default();
    changes.add(UtxoAdd::new(outpoint, txout, true, 7));

    bitcoin_rs_utxo::contract::commit_block_changes(
        &ctx.chain.utxo.fixture_set(),
        &changes,
        &Hash256::default(),
    )
    .unwrap_or_else(|err| panic!("commit_block failed: {err}"));

    let snapshot = ctx.chain.coin_stats.snapshot();
    assert_eq!(snapshot.utxo_count, 1);
    assert_eq!(snapshot.total_amount, 125_000);
}

#[test]
fn connected_log_blocks_resolve_metadata_without_header_bytes() {
    let genesis = Network::Regtest.genesis_block();
    let mut child = genesis.clone();
    child.header.prev_blockhash = genesis.block_hash();
    child.header.nonce = child.header.nonce.wrapping_add(1);
    child.header.time = child.header.time.wrapping_add(600);

    let ctx = Context::new();
    ctx.chain.add_block(BlockRecord::from_block(0, &genesis));
    ctx.chain.add_block(BlockRecord::from_block(1, &child));

    for (height, source) in [(0_u32, &genesis), (1_u32, &child)] {
        let resolved = ctx
            .chain
            .block_by_height(height)
            .unwrap_or_else(|| panic!("the log resolves height {height}"));
        assert_eq!(resolved.height, height);
        assert_eq!(resolved.hash, source.block_hash());
        assert_eq!(resolved.time, source.header.time);
        assert_eq!(resolved.body_size, consensus_bytes(source).len());
        assert_eq!(resolved.tx_count, source.txs.len());
        assert!(
            resolved.header_bytes().is_none(),
            "the log stores no header at height {height}"
        );
    }
}

#[test]
fn context_reads_metadata_only_block_record_from_body_source() {
    let block = Network::Regtest.genesis_block();
    let body = consensus_bytes(&block);
    let record = BlockRecord::from_block(0, &block);
    let source = Arc::new(BlockBodies {
        bodies: vec![(0, record.hash, body.clone())],
    });
    let ctx = Context::from_handles(ContextHandles {
        chain: ChainHandles {
            block_body_source: Some(source),
            ..ChainHandles::default()
        },
        ..ContextHandles::default()
    });
    ctx.chain.add_block(record.clone());

    assert_eq!(record.body_size, consensus_bytes(&block).len());
    assert_eq!(
        ctx.chain.block_body_bytes(&record).as_deref(),
        Some(body.as_slice())
    );
    let expected_hex = body.to_lower_hex_string();
    assert_eq!(
        ctx.chain.block_body_hex(&record).as_deref(),
        Some(expected_hex.as_str())
    );
}

#[test]
fn header_hex_is_unchanged_by_sourcing_the_header_from_the_tree() {
    let block = Network::Regtest.genesis_block();
    let ctx = Arc::new(Context::new());
    {
        let mut tree = ctx.chain.block_tree.write();
        let _ = tree.insert_node(None, block.header, bitcoin_rs_chain::NodeStatus::Active);
    }
    let hash = Hash256::from(block.block_hash());
    let Some(record) = ctx.chain.block_by_hash(hash) else {
        panic!("the tree knows this hash");
    };

    assert_eq!(
        record.header_hex(),
        consensus_bytes(&block.header).to_lower_hex_string()
    );
    assert_eq!(
        record.header_hex().len(),
        bitcoin_rs_primitives::Header::LEN * 2
    );
}

#[test]
fn block_by_hash_answers_with_the_tree_header_for_a_cached_record() {
    let block = Network::Regtest.genesis_block();
    let ctx = Arc::new(Context::new());
    {
        let mut tree = ctx.chain.block_tree.write();
        let _ = tree.insert_node(None, block.header, bitcoin_rs_chain::NodeStatus::Active);
    }
    let cached = BlockRecord::from_block(0, &block);
    let hash = Hash256::from(cached.hash);
    let expected_body_size = cached.body_size;
    let expected_tx_count = cached.tx_count;
    assert!(cached.header_bytes().is_none(), "the log stores no header");
    ctx.chain.add_block(cached);

    let Some(record) = ctx.chain.block_by_hash(hash) else {
        panic!("the tree knows this hash");
    };
    assert_eq!(
        record.header_bytes().map(<[u8; 80]>::as_slice),
        Some(consensus_bytes(&block.header).as_slice()),
        "the resolved record must carry the tree's header"
    );
    assert_eq!(
        record.body_size, expected_body_size,
        "the cached body size must survive the header splice"
    );
    assert_eq!(
        record.tx_count, expected_tx_count,
        "the cached transaction count must survive the header splice"
    );
}
#[test]
fn block_by_hash_ignores_log_records_the_tree_does_not_know() {
    let ctx = Context::new();
    let hash = Hash256::from_le_bytes(&[3_u8; 32]);
    ctx.chain
        .add_block(BlockRecord::synthetic(3, BlockHash::from(hash)));

    assert!(ctx.chain.block_by_hash(hash).is_none());
}

#[test]
fn synthetic_record_has_no_header_and_renders_empty_hex() {
    let record = BlockRecord::synthetic(7, BlockHash::from(Hash256::from_le_bytes(&[3_u8; 32])));

    assert!(record.header_bytes().is_none());
    assert_eq!(record.header_hex(), "");
}

#[test]
fn tree_derived_record_carries_the_header() {
    use bitcoin_rs_chain::NodeStatus;
    use bitcoin_rs_primitives::Header;

    let ctx = Context::new();
    let header = Header {
        version: 1,
        prev_blockhash: BlockHash::default(),
        merkle_root: Hash256::default(),
        time: 1_000_000,
        bits: CompactTarget::from_consensus(0x207f_ffff),
        nonce: 7,
    };
    let hash = {
        let mut tree = ctx.chain.block_tree.write();
        let id = tree
            .insert_node(None, header, NodeStatus::Active)
            .expect("genesis inserts");
        tree.node(id).expect("inserted node").hash
    };

    let record = ctx
        .chain
        .block_by_hash(hash)
        .expect("tree resolves the hash");

    assert_eq!(
        record.header_bytes().map(|bytes| &bytes[..]),
        Some(consensus_bytes(&header).as_slice()),
        "the tree-derived record must carry the header the tree holds"
    );
    assert_eq!(
        record.header_hex(),
        consensus_bytes(&header).to_lower_hex_string()
    );
}

#[test]
fn height_for_hash_returns_none_when_tree_empty() {
    let ctx = Context::new();
    let unknown = bitcoin_rs_primitives::Hash256::from_le_bytes(&[0xff_u8; 32]);

    assert!(ctx.chain.height_for_hash(unknown).is_none());
}
#[test]
fn block_by_height_prefers_tree_identity_over_stale_cache() -> Result<(), Box<dyn std::error::Error>>
{
    use bitcoin_rs_chain::NodeStatus;
    use bitcoin_rs_primitives::Header;

    let ctx = Context::new();
    let (child_hash, stale_hash) = {
        let mut tree = ctx.chain.block_tree.write();
        let genesis = Header {
            version: 1,
            prev_blockhash: BlockHash::default(),
            merkle_root: Hash256::default(),
            time: 1_000_000,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        };
        let genesis_id = tree.insert_node(None, genesis, NodeStatus::Active)?;
        let mut child = Header {
            version: 1,
            prev_blockhash: genesis.compute_hash(),
            merkle_root: Hash256::default(),
            time: 1_000_900,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        };
        child.nonce = 1;
        let child_id = tree.insert_node(Some(genesis_id), child, NodeStatus::Active)?;
        let child_hash = tree.node(child_id)?.hash;
        let applied_tip = tree
            .tip()
            .ok_or_else(|| std::io::Error::other("missing child tip"))?;
        ctx.chain
            .applied_tip
            .store(Some(Arc::new((*applied_tip).clone())));
        let stale_hash = Hash256::from_le_bytes(&[0xa5_u8; 32]);
        ctx.chain
            .add_block(BlockRecord::synthetic(1, BlockHash::from(stale_hash)));
        (child_hash, stale_hash)
    };

    assert_ne!(child_hash, stale_hash, "test fixture hashes must differ");
    let found = ctx
        .chain
        .block_by_height(1)
        .ok_or_else(|| std::io::Error::other("tree child missing at height 1"))?;
    assert_eq!(
        found.hash,
        BlockHash::from(child_hash),
        "active-tree identity must win over a stale cached hash"
    );
    assert_eq!(found.height, 1);
    Ok(())
}

#[test]
fn height_lookups_follow_applied_tip_when_header_fork_leads()
-> Result<(), Box<dyn std::error::Error>> {
    use bitcoin_rs_chain::NodeStatus;
    use bitcoin_rs_primitives::Header;

    let ctx = Context::new();
    let (applied_tip, header_tip) = {
        let mut tree = ctx.chain.block_tree.write();
        let genesis = Header {
            version: 1,
            prev_blockhash: BlockHash::default(),
            merkle_root: Hash256::default(),
            time: 1_000_000,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        };
        let genesis_id = tree.insert_node(None, genesis, NodeStatus::Active)?;
        let applied = Header {
            version: 1,
            prev_blockhash: genesis.compute_hash(),
            merkle_root: Hash256::default(),
            time: 1_000_900,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 1,
        };
        let applied_id = tree.insert_node(Some(genesis_id), applied, NodeStatus::Active)?;
        let applied_tip = tree
            .tip()
            .ok_or_else(|| std::io::Error::other("missing applied tip"))?;
        assert_eq!(applied_tip.tip_id, applied_id);

        let fork = Header {
            version: 1,
            prev_blockhash: genesis.compute_hash(),
            merkle_root: Hash256::default(),
            time: 1_000_901,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 2,
        };
        let fork_id = tree.insert_node(Some(genesis_id), fork, NodeStatus::HeaderValid)?;
        let fork_tip = Header {
            version: 1,
            prev_blockhash: fork.compute_hash(),
            merkle_root: Hash256::default(),
            time: 1_001_800,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 3,
        };
        let header_tip_id = tree.insert_node(Some(fork_id), fork_tip, NodeStatus::HeaderValid)?;
        let header_tip = tree
            .tip()
            .ok_or_else(|| std::io::Error::other("missing header tip"))?;
        assert_eq!(header_tip.tip_id, header_tip_id);
        (applied_tip, header_tip)
    };

    ctx.chain
        .applied_tip
        .store(Some(Arc::new((*applied_tip).clone())));
    ctx.chain
        .chain_tip
        .store(Some(Arc::new((*header_tip).clone())));
    ctx.chain
        .add_block(BlockRecord::synthetic(2, BlockHash::from(header_tip.hash)));

    assert_eq!(
        ctx.chain.active_hash_at_height(1),
        Some(applied_tip.hash),
        "height lookup must stay on the applied branch"
    );
    assert_eq!(ctx.chain.block_hash_at_height(1), Some(applied_tip.hash));
    assert_eq!(
        ctx.chain
            .block_by_height(1)
            .map(|record| Hash256::from(record.hash)),
        Some(applied_tip.hash)
    );
    assert!(ctx.chain.block_hash_at_height(2).is_none());
    assert!(ctx.chain.block_by_height(2).is_none());
    Ok(())
}

#[test]
#[expect(clippy::too_many_lines)]
fn ibd_latch_judges_the_contexts_own_tree() {
    use alloc::sync::Arc;

    fn insert_recent_tip(ctx: &Context, now: u64) -> TipSnapshot {
        let genesis = Network::Regtest.genesis_block();
        let mut tree = ctx.chain.block_tree.write();
        let genesis_id = tree
            .insert_node(
                None,
                genesis.header,
                bitcoin_rs_chain::node::NodeStatus::Active,
            )
            .expect("genesis insert");
        let mut child = genesis.header;
        child.prev_blockhash = genesis.block_hash();
        child.time = u32::try_from(now - 60).unwrap_or(u32::MAX);
        child.nonce = 1;
        let child_id = tree
            .insert_node(
                Some(genesis_id),
                child,
                bitcoin_rs_chain::node::NodeStatus::Active,
            )
            .expect("child insert");
        let node = tree.node(child_id).expect("inserted node");
        TipSnapshot {
            tip_id: child_id,
            height: node.height,
            chainwork: node.chainwork,
            hash: node.hash,
            chain_tx_count: node.chain_tx_count,
        }
    }

    let chain_tip = TipReader::new(Arc::new(ArcSwapOption::empty()));
    let applied_tip = Arc::new(ArcSwapOption::empty());

    let block_tree = Arc::new(RwLock::new(bitcoin_rs_chain::BlockTree::new()));
    let status: Arc<dyn bitcoin_rs_index::DerivedIndexCapabilitySource> = Arc::new(ReadySource);
    let ctx = Context::from_handles(ContextHandles {
        chain: ChainHandles {
            chain_tip: chain_tip.clone(),
            applied_tip: TipReader::new(Arc::clone(&applied_tip)),
            active_tip_wait: None,
            chain_transition: bitcoin_rs_chain::TransitionDomain::new().stable_read(),
            progress: bitcoin_rs_chain::ChainProgressReader::new(
                chain_tip,
                TipReader::new(Arc::clone(&applied_tip)),
                BlockTreeReader::new(Arc::clone(&block_tree)),
                Arc::new(bitcoin_rs_chain::InitialBlockDownload::new(
                    TipReader::new(Arc::clone(&applied_tip)),
                    BlockTreeReader::new(Arc::clone(&block_tree)),
                )),
            ),
            blocks: BlockLogReader::fixture_empty(),
            utxo: bitcoin_rs_utxo::UtxoReader::new(Arc::new(bitcoin_rs_utxo::UtxoSet::new())),
            coin_stats: Arc::new(bitcoin_rs_utxo::stats::CoinStatsListener::new(
                bitcoin_rs_utxo::stats::CoinStats::default(),
            )),
            prune_service: None,
            chain_control: None,
            block_tree: BlockTreeReader::new(Arc::clone(&block_tree)),
            chain_network: Network::Mainnet,
            block_body_source: None,
            block_undo_source: None,
            closed_for_recovery: LatchReader::new(Arc::new(core::sync::atomic::AtomicBool::new(
                false,
            ))),
            rollback_warnings: None,
        },
        mempool: MempoolHandles {
            gateway: Arc::new(MempoolGateway::new(
                Arc::new(RwLock::new(Mempool::new(MempoolLimits::default()))),
                None,
                ValidationEngine::Native,
                None,
            )),
        },
        indexes: IndexHandles {
            derived_index: None,
            esplora_tx_index: None,
            script_index: None,
            compact_filters: None,
            derived_index_status: Some(Arc::clone(&status)),
        },
        network: NetworkHandles::default(),
        mining: MiningHandles {
            mining_control: None,
        },
        ..ContextHandles::default()
    });

    let now = 1_800_000_000_u64;
    let tip = insert_recent_tip(&ctx, now);
    ctx.chain.applied_tip.store(Some(Arc::new(tip)));
    assert!(
        !ctx.chain
            .progress
            .initial_block_download(now, Network::Regtest),
        "the latch must judge the tip it reaches through the context's tree"
    );
    assert!(
        Arc::ptr_eq(
            ctx.indexes
                .derived_index_status
                .as_ref()
                .expect("index status keeps its own slot"),
            &status
        ),
        "the txindex status source must be shared with caller"
    );
}
