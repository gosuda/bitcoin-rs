use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use arc_swap::ArcSwapOption;
// Wire seam: byte-array access on the retained bitcoin:: wire hash types.
use bitcoin::hashes::Hash;
use bitcoin_rs_chain::{BlockTree, NodeStatus, TipSnapshot};
use bitcoin_rs_mempool::{Mempool, MempoolLimits};
use bitcoin_rs_p2p::{PeerInfo, PeerLease, PeerSource, PeerTable, StagedBlock};
use bitcoin_rs_primitives::encode::double_sha256;
use bitcoin_rs_primitives::{
    Block, BlockHash, Hash256, Header, Network, OutPoint, Tx, TxIn, TxOut, Txid, consensus_bytes,
};
use bitcoin_rs_script::push_int;
use bitcoin_rs_storage::StorageError;
use bitcoin_rs_utxo::UtxoSet;
use crossbeam_channel::unbounded;
use hashbrown::HashMap;
use metrics::Counter;
use metrics::CounterFn;
use metrics::Gauge;
use metrics::GaugeFn;
use metrics::Histogram;
use metrics::HistogramFn;
use metrics::Key;
use metrics::KeyName;
use metrics::Metadata;
use metrics::Recorder;
use metrics::SharedString;
use metrics::Unit;
use parking_lot::Mutex;
use parking_lot::RwLock;

use super::BlockSync;
use super::InboundHeaders;
use super::Inventory;
use super::Message;
use crate::apply::Chainstate;

fn check_sync_frontier_pair(
    sync: &BlockSync,
    rx: &crossbeam_channel::Receiver<Message>,
    addr: SocketAddr,
    applied: &TipSnapshot,
    target: &TipSnapshot,
) -> Result<(), Box<dyn std::error::Error>> {
    let expected = bitcoin_rs_chain::plan_reorg(
        &sync.handles.block_tree.read(),
        applied.tip_id,
        target.tip_id,
    )
    .ok();
    sync.handles
        .applied_tip
        .store(Some(Arc::new(applied.clone())));
    sync.handles.chain_tip.store(Some(Arc::new(target.clone())));
    assert_eq!(
        sync.outweighed_branch_target(),
        expected
            .as_ref()
            .filter(|plan| !plan.disconnect.is_empty())
            .map(|_| target.tip_id),
        "branch gate differs: {applied:?} -> {target:?}; indexed or parent-walk fixture"
    );
    sync.install_budget(super::default_sync_budget());
    let outcome = sync.send_getdata_for_pending_blocks(addr, true, 100, target, applied);
    let expected_ids = expected
        .as_ref()
        .map(|plan| plan.connect.as_slice())
        .unwrap_or_default();
    if expected_ids.is_empty() {
        assert!(!outcome.sent);
        assert!(rx.try_recv().is_err());
        return Ok(());
    }
    assert!(outcome.sent);
    let Message::GetData(inventory) = rx.try_recv()? else {
        return Err("expected witness getdata".into());
    };
    let requested = witness_block_inventory(inventory)?;
    let tree = sync.handles.block_tree.read();
    let expected_hashes = expected_ids
        .iter()
        .take(requested.len())
        .map(|id| tree.node(*id).map(|node| BlockHash(node.hash)))
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(requested, expected_hashes);
    assert!(!requested.is_empty());
    assert!(rx.try_recv().is_err());
    Ok(())
}

#[test]
fn tick_allows_demoted_peer_when_it_is_the_only_eligible_peer()
-> Result<(), Box<dyn std::error::Error>> {
    let (sync, peers, block_tree, applied_tip, expected) = sync_with_header_chain(4)?;
    install_budget(
        &sync,
        super::SyncBudget {
            max_pending_blocks: 2,
            max_peer_inflight: 2,
            getdata_batch_limit: 2,
            pending_timeout: Duration::ZERO,
            ..super::default_sync_budget()
        },
    );
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
    let rx = connect_peer(&peers, synthetic_peer(addr, 100));

    sync.tick();

    assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
    let Message::GetData(first_inventory) = rx.try_recv()? else {
        return Err(std::io::Error::other("expected first getdata").into());
    };
    assert_eq!(witness_block_inventory(first_inventory)?, expected[..2]);
    let headers = rx.try_recv()?;
    if !matches!(headers, Message::GetHeaders(_)) {
        return Err(std::io::Error::other("expected getheaders").into());
    }

    sync.tick();

    let Message::GetData(retry_inventory) = rx.try_recv()? else {
        return Err(std::io::Error::other("expected retry getdata").into());
    };
    assert_eq!(witness_block_inventory(retry_inventory)?, expected[..2]);
    Ok(())
}

#[test]
fn unsolicited_stale_block_retries_from_resolved_header_height()
-> Result<(), Box<dyn std::error::Error>> {
    let genesis = Network::Regtest.genesis_block();
    let block1 = mined_block_with_prev_hash(genesis.block_hash(), 1, vec![coinbase_transaction(1)]);
    let block2 = mined_block_with_prev_hash(block1.block_hash(), 2, vec![coinbase_transaction(2)]);
    let block1_hash = block1.block_hash();
    let expected_hash = block2.block_hash();
    let mut tree = BlockTree::new();
    let genesis_id = tree.insert_node(None, genesis.header, NodeStatus::HeaderValid)?;
    let block1_id = tree.insert_node(Some(genesis_id), block1.header, NodeStatus::HeaderValid)?;
    tree.insert_node(Some(block1_id), block2.header, NodeStatus::HeaderValid)?;
    let chain_tip = tree.tip_handle();
    let block_tree = Arc::new(RwLock::new(tree));
    let applied_tip = Arc::new(ArcSwapOption::empty());
    let peers = Arc::new(PeerTable::new());
    let (_inbound_headers_tx, inbound_headers_rx_raw) = unbounded::<InboundHeaders>();
    let inbound_headers_rx = Arc::new(Mutex::new(inbound_headers_rx_raw));
    let (inbound_blocks_tx, inbound_blocks_rx_raw) = unbounded::<bitcoin_rs_p2p::InboundBlock>();
    let inbound_blocks_rx = Arc::new(Mutex::new(inbound_blocks_rx_raw));
    let handles = apply_handles(
        Arc::clone(&chain_tip),
        Arc::clone(&applied_tip),
        Arc::clone(&block_tree),
    );
    let sync = BlockSync::for_test(
        handles,
        Arc::clone(&peers),
        inbound_headers_rx,
        inbound_blocks_rx,
    );
    install_budget(
        &sync,
        super::SyncBudget {
            getdata_batch_limit: 2,
            received_timeout: Duration::ZERO,
            ..super::default_sync_budget()
        },
    );
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
    let rx = connect_peer(&peers, synthetic_peer(addr, 100));

    sync.tick();

    assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
    let Message::GetData(initial) = rx.try_recv()? else {
        return Err(std::io::Error::other("expected initial getdata").into());
    };
    assert_eq!(
        witness_block_inventory(initial)?,
        alloc::vec![block1_hash, expected_hash]
    );
    let _headers = rx.try_recv()?;
    {
        let mut window = sync.download_window.lock();
        window.mark_applied(&Hash256::from_le_bytes(block1_hash.as_bytes()));
        window.mark_applied(&Hash256::from_le_bytes(expected_hash.as_bytes()));
    }

    inbound_blocks_tx.send(bitcoin_rs_p2p::InboundBlock::from_decoded(block2))?;
    sync.drain_inbound_blocks();

    assert_eq!(sync.block_stager.lock().received_len(), 0);
    assert_eq!(sync.download_window.lock().received_len(), 0);

    sync.tick();

    let Message::GetData(retry) = rx.try_recv()? else {
        return Err(std::io::Error::other("expected height-2 retry getdata").into());
    };
    assert_eq!(witness_block_inventory(retry)?, alloc::vec![expected_hash]);
    Ok(())
}

/// Cross-tick regression for the bounded prefix-race-before-fanout
/// handoff: a probe created below the threshold must defer fanout when the
/// eligible count reaches the threshold on a following tick while the
/// probe is still fresh, then fanout must engage once the injected time
/// crosses the `stall_timeout_initial` deadline. Exercises the real
/// `tick()` / `configure_request_mode` / `set_fanout_eligible_peers`
/// path for probe creation and the deferral, then injects a future
/// `Instant` (the only available time seam, since `tick()` reads
/// `Instant::now()`) to cross the deadline. This is the exact cross-tick
/// boundary test; the direct window-boundary test lives in
/// `window::tests::fanout_cancels_prefix_probe_without_rearming_it`. No
/// sleeps, no network.
#[test]
fn tick_fanout_deferred_for_fresh_probe_engages_at_deadline()
-> Result<(), Box<dyn std::error::Error>> {
    // A 16-block chain: the deep single-peer window takes all 16 while
    // the one-shot probe sends the first 8 (PREFIX_PROBE_BLOCK_LIMIT), so
    // the probe getdata is distinguishable from the deep getdata.
    let (sync, peers, block_tree, applied_tip, expected) = sync_with_header_chain(16)?;
    install_budget(&sync, super::default_sync_budget());

    // Two eligible peers: below the 8-peer fanout threshold. The owner
    // (highest) takes the deep window; the alternate is the probe racer.
    let owner_addr = test_addr(9401, 0)?;
    let alternate_addr = test_addr(9401, 1)?;
    let owner_rx = connect_peer(&peers, eligible_peer(owner_addr, 201));
    let alternate_rx = connect_peer(&peers, eligible_peer(alternate_addr, 200));

    // Tick 1: below the threshold, a prefix probe is created. The owner
    // receives the deep getdata (all 16) and the alternate receives the
    // one-shot probe getdata (the first 8).
    sync.tick();
    assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
    assert_eq!(
        witness_block_inventory(next_getdata(&owner_rx)?)?,
        expected,
        "the deep owner must receive the full window"
    );
    assert_eq!(
        witness_block_inventory(next_getdata(&alternate_rx)?)?,
        expected[..8],
        "the alternate must receive the one-shot probe prefix"
    );
    assert!(
        !sync.download_window.lock().fanout_active(),
        "below the threshold fanout must stay off"
    );

    // Reach the fanout threshold on the following tick: add six more
    // eligible peers (eight total) and tick again. The probe is still
    // fresh (age well under stall_timeout_initial = 2s), so the bounded
    // deferral holds fanout off and the probe survives the transition.
    for idx in 2..super::MIN_PEERS_FOR_FANOUT {
        connect_peer(&peers, eligible_peer(test_addr(9401, idx)?, 200));
    }
    sync.tick();
    assert!(
        !sync.download_window.lock().fanout_active(),
        "a fresh prefix probe must defer the threshold-crossing tick"
    );

    // Cross the injected time deadline measured from the active probe's
    // stored `started_at`. The cross-tick path cannot control the
    // `Instant::now()` used when the probe is created, so read it back and
    // add exactly `stall_timeout_initial`. Then assert the planned
    // duration equals the budget before engaging fanout.
    let mut window = sync.download_window.lock();
    let started_at = window
        .active_prefix_probe_started_at()
        .ok_or_else(|| std::io::Error::other("probe must remain active after deferral"))?;
    let budget = super::default_sync_budget();
    let planned_duration = budget.stall_timeout_initial;
    let deadline = started_at + planned_duration;
    assert_eq!(
        deadline - started_at,
        planned_duration,
        "planned deadline must be exactly stall_timeout_initial after probe start"
    );
    window.set_fanout_eligible_peers(super::MIN_PEERS_FOR_FANOUT, deadline);
    assert!(
        window.fanout_active(),
        "fanout must engage at the stall_timeout_initial deadline"
    );
    assert!(
        window.prefix_probe_plan().is_none(),
        "no probe plan may remain once fanout engages"
    );
    Ok(())
}

/// Seven eligible peers plus one ineligible candidate: were the
/// ineligible peer counted, fan-out (many shallow getdatas) would engage;
/// instead the window collapses to one deep single-peer batch. When the
/// ineligible peer is the highest candidate (`serves_fallback`), it also
/// pins that the fallback still uses it — the pre-fan-out shipped
/// behavior (an inbound-only node must still sync).
fn assert_fallback_with_ineligible_candidate(
    ineligible: PeerInfo,
    serves_fallback: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let (sync, peers, block_tree, applied_tip, expected) =
        sync_with_header_chain(u32::try_from(super::PENDING_BUDGET)?)?;
    let ineligible_rx = connect_peer(&peers, ineligible);
    let mut rxs = Vec::new();
    for idx in 0..super::MIN_PEERS_FOR_FANOUT - 1 {
        let addr = test_addr(9230, idx)?;
        rxs.push(connect_peer(
            &peers,
            eligible_peer(addr, 300 - i32::try_from(idx)?),
        ));
    }

    sync.tick();

    assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
    let deep_rx = if serves_fallback {
        &ineligible_rx
    } else {
        &rxs[0]
    };
    let Message::GetData(inventory) = deep_rx.try_recv()? else {
        return Err(std::io::Error::other("expected one deep fallback getdata").into());
    };
    assert_eq!(witness_block_inventory(inventory)?, expected);
    if !serves_fallback {
        assert!(
            ineligible_rx.try_recv().is_err(),
            "ineligible peer must receive nothing"
        );
    }
    for rx in &rxs[usize::from(!serves_fallback)..] {
        assert_eq!(witness_block_inventory(next_getdata(rx)?)?, expected[..8]);
    }
    Ok(())
}

#[test]
fn stalled_frontier_peer_disconnected_after_adaptive_timeout_and_stripe_requeued()
-> Result<(), Box<dyn std::error::Error>> {
    // R8 core scenario and the terminator for the U6 wedge's bounded
    // cycle (and the first-audit ADV-2 shape: the staller is the
    // highest-advertising peer, holding the front on claimed height it
    // never serves). The 1-minute pending timeout can never fire inside
    // this test, so the staller disconnect is the ONLY recovery path.
    let budget = super::SyncBudget {
        stall_timeout_initial: Duration::from_millis(100),
        ..wedge_budget(super::PENDING_TIMEOUT)
    };
    let (sync, peers, expected, rxs, _blocks_tx) = staged_count_wedge(budget)?;
    let staller = test_addr(9320, 0)?;

    // Cold-start disarm: the wedge fixture never advances the window
    // front, so the cadence EWMA would stay unseeded and conviction
    // would defer to the 60s pending-timeout fallback (the cold-start
    // suppression, pinned at the window level). Seed it at 50ms — the
    // decay floor stays max(2x50ms, 100ms) = the injected initial
    // threshold — so this test keeps pinning the adaptive-timeout fire.
    sync.download_window
        .lock()
        .seed_front_cadence_for_test(50, Instant::now());

    // Tick 2: the wedge forms (staged 14 + pending 2 at the count
    // budget) and the stall episode starts on the front-stripe owner.
    sync.tick();
    {
        let window = sync.download_window.lock();
        assert_eq!(window.received_len(), 14);
        assert_eq!(window.pending_len(), 2);
        assert_eq!(
            window.stalling_peer().map(|(addr, _)| addr),
            Some(staller),
            "the front-stripe owner must be the observed staller"
        );
    }

    // Past the adaptive threshold: the staller is disconnected, its
    // front stripe re-queues, and a healthy peer is asked for it in the
    // same tick — with the staged set intact (no prune involvement).
    std::thread::sleep(Duration::from_millis(150));
    sync.tick();

    assert!(
        !peers.is_connected(staller),
        "staller's outbound lease must be revoked"
    );
    assert!(
        sync.download_window
            .lock()
            .peer_in_staller_cooldown(staller, Instant::now()),
        "disconnected staller must enter the cooldown"
    );
    assert_no_getdata(&rxs[0])?;
    let mut rerequested = Vec::new();
    for rx in &rxs[1..] {
        while let Ok(message) = rx.try_recv() {
            if let Message::GetData(inventory) = message {
                rerequested.extend(witness_block_inventory(inventory)?);
            }
        }
    }
    assert_eq!(
        rerequested,
        expected[..2],
        "the stalled front stripe must be re-requested from a healthy peer"
    );
    assert_eq!(
        sync.block_stager.lock().received_len(),
        14,
        "staged progress must survive the staller disconnect"
    );
    {
        let window = sync.download_window.lock();
        assert_eq!(window.pending_len(), 2);
        for front in &expected[..2] {
            assert!(window.contains_pending(&Hash256::from_le_bytes(front.as_bytes())));
        }
    }
    Ok(())
}

#[test]
fn clean_fast_path_caps_request_at_peer_height() -> Result<(), Box<dyn std::error::Error>> {
    let (sync, peers, block_tree, applied_tip, expected) = sync_with_header_chain(8)?;
    install_budget(
        &sync,
        super::SyncBudget {
            max_pending_blocks: 4,
            max_peer_inflight: 4,
            getdata_batch_limit: 4,
            ..super::default_sync_budget()
        },
    );
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
    let rx = connect_peer(&peers, synthetic_peer(addr, 2));

    sync.tick();

    assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
    let Message::GetData(inventory) = rx.try_recv()? else {
        return Err(std::io::Error::other("expected getdata").into());
    };
    assert_eq!(witness_block_inventory(inventory)?, expected[..2]);
    assert!(rx.try_recv().is_err());

    sync.tick();

    assert!(rx.try_recv().is_err());
    Ok(())
}

struct ExhaustionFixture {
    sync: BlockSync,
    stalled_rx: crossbeam_channel::Receiver<Message>,
    healthy_rx: crossbeam_channel::Receiver<Message>,
    block1_hash: BlockHash,
    block2_hash: BlockHash,
}

fn staging_exhaustion_fixture() -> Result<ExhaustionFixture, Box<dyn std::error::Error>> {
    let genesis = Network::Regtest.genesis_block();
    let block1 = mined_block_with_prev_hash(genesis.block_hash(), 1, vec![coinbase_transaction(1)]);
    let block2 = mined_block_with_prev_hash(block1.block_hash(), 2, vec![coinbase_transaction(2)]);
    let block3 = mined_block_with_prev_hash(block2.block_hash(), 3, vec![coinbase_transaction(3)]);
    let block1_hash = block1.block_hash();
    let block2_hash = block2.block_hash();
    let mut tree = BlockTree::new();
    let genesis_id = tree.insert_node(None, genesis.header, NodeStatus::HeaderValid)?;
    let block1_id = tree.insert_node(Some(genesis_id), block1.header, NodeStatus::HeaderValid)?;
    let block2_id = tree.insert_node(Some(block1_id), block2.header, NodeStatus::HeaderValid)?;
    tree.insert_node(Some(block2_id), block3.header, NodeStatus::HeaderValid)?;

    let chain_tip = tree.tip_handle();
    let block_tree = Arc::new(RwLock::new(tree));
    let applied_tip = Arc::new(ArcSwapOption::empty());
    let peers = Arc::new(PeerTable::new());
    let (_inbound_headers_tx, inbound_headers_rx_raw) = unbounded::<InboundHeaders>();
    let inbound_headers_rx = Arc::new(Mutex::new(inbound_headers_rx_raw));
    let (inbound_blocks_tx, inbound_blocks_rx_raw) = unbounded::<bitcoin_rs_p2p::InboundBlock>();
    let inbound_blocks_rx = Arc::new(Mutex::new(inbound_blocks_rx_raw));
    let handles = apply_handles(
        Arc::clone(&chain_tip),
        Arc::clone(&applied_tip),
        Arc::clone(&block_tree),
    );
    let sync = BlockSync::for_test(
        handles,
        Arc::clone(&peers),
        inbound_headers_rx,
        inbound_blocks_rx,
    );
    // Staging byte budget that exactly one staged block exhausts.
    install_budget(
        &sync,
        super::SyncBudget {
            max_received_bytes: consensus_bytes(&block2).len(),
            getdata_batch_limit: 2,
            pending_timeout: Duration::ZERO,
            received_timeout: Duration::from_millis(100),
            ..super::default_sync_budget()
        },
    );
    let stalled_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
    let healthy_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8334);
    let stalled_rx = connect_peer(&peers, synthetic_peer(stalled_addr, 100));

    sync.tick();

    assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
    let Message::GetData(inventory) = stalled_rx.try_recv()? else {
        return Err(std::io::Error::other("expected getdata").into());
    };
    assert_eq!(
        witness_block_inventory(inventory)?,
        alloc::vec![block1_hash, block2_hash]
    );
    let _headers = stalled_rx.try_recv()?;

    // Deliver only the successor: it stages (waiting on block1, which the
    // stalled peer will never send) and exactly exhausts the staging byte
    // budget, closing the request gate.
    inbound_blocks_tx.send(bitcoin_rs_p2p::InboundBlock::from_decoded(block2))?;
    sync.drain_inbound_blocks();
    assert!(!sync.download_window.lock().has_request_capacity());

    let healthy_rx = connect_peer(&peers, synthetic_peer(healthy_addr, 100));

    Ok(ExhaustionFixture {
        sync,
        stalled_rx,
        healthy_rx,
        block1_hash,
        block2_hash,
    })
}

const DETERMINISTIC_PROXY_BLOCKS: usize = 24;
const DETERMINISTIC_PROXY_TIP_HEIGHT: u32 = 24;
const DETERMINISTIC_PROXY_HEADER_HEIGHT: u32 = 96;

struct DeterministicProxyFixture {
    sync: BlockSync,
    applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
    block_tree: Arc<RwLock<BlockTree>>,
    inbound_blocks_tx: crossbeam_channel::Sender<bitcoin_rs_p2p::InboundBlock>,
    outbound_rx: crossbeam_channel::Receiver<Message>,
    blocks: Vec<Block>,
}

fn deterministic_proxy_fixture() -> Result<DeterministicProxyFixture, Box<dyn std::error::Error>> {
    let genesis = Network::Regtest.genesis_block();
    let mut tree = BlockTree::new();
    let genesis_id = tree.insert_node(None, genesis.header, NodeStatus::HeaderValid)?;
    let mut tip_id = genesis_id;
    let mut prev_hash = genesis.block_hash();
    let mut blocks = Vec::with_capacity(DETERMINISTIC_PROXY_BLOCKS);

    for height in 1_u32..=DETERMINISTIC_PROXY_TIP_HEIGHT {
        let block =
            mined_block_with_prev_hash(prev_hash, height, vec![coinbase_transaction(height)]);
        tip_id = tree.insert_node(Some(tip_id), block.header, NodeStatus::HeaderValid)?;
        prev_hash = block.block_hash();
        blocks.push(block);
    }
    for height in
        DETERMINISTIC_PROXY_TIP_HEIGHT.saturating_add(1)..=DETERMINISTIC_PROXY_HEADER_HEIGHT
    {
        let header = test_header(prev_hash, height);
        tip_id = tree.insert_node(Some(tip_id), header, NodeStatus::HeaderValid)?;
        prev_hash = header.compute_hash();
    }

    let chain_tip = tree.tip_handle();
    let block_tree = Arc::new(RwLock::new(tree));
    let applied_tip = Arc::new(ArcSwapOption::empty());
    let peers = Arc::new(PeerTable::new());
    let (_inbound_headers_tx, inbound_headers_rx_raw) = unbounded::<InboundHeaders>();
    let inbound_headers_rx = Arc::new(Mutex::new(inbound_headers_rx_raw));
    let (inbound_blocks_tx, inbound_blocks_rx_raw) = unbounded::<bitcoin_rs_p2p::InboundBlock>();
    let inbound_blocks_rx = Arc::new(Mutex::new(inbound_blocks_rx_raw));
    let handles = apply_handles(
        Arc::clone(&chain_tip),
        Arc::clone(&applied_tip),
        Arc::clone(&block_tree),
    );
    let sync = BlockSync::for_test(
        handles,
        Arc::clone(&peers),
        inbound_headers_rx,
        inbound_blocks_rx,
    );
    install_budget(
        &sync,
        super::SyncBudget {
            max_pending_blocks: DETERMINISTIC_PROXY_BLOCKS,
            max_pending_bytes: usize::MAX,
            max_received_blocks: DETERMINISTIC_PROXY_BLOCKS,
            max_received_bytes: usize::MAX,
            max_peer_inflight: DETERMINISTIC_PROXY_BLOCKS,
            getdata_batch_limit: DETERMINISTIC_PROXY_BLOCKS,
            ..super::default_sync_budget()
        },
    );

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
    let outbound_rx = connect_peer(&peers, synthetic_peer(addr, 100));

    Ok(DeterministicProxyFixture {
        sync,
        applied_tip,
        block_tree,
        inbound_blocks_tx,
        outbound_rx,
        blocks,
    })
}

struct ApplyCacheFixture {
    sync: BlockSync,
    blocks: Vec<Block>,
    applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
    chain_tip: Arc<ArcSwapOption<TipSnapshot>>,
}

/// Builds a regtest chain with `body_height` mined block bodies followed by
/// `header_only` header-only blocks, applies genesis, and returns a fixture
/// whose stager is empty so individual rounds can stage bodies directly and
/// exercise the apply-side cache miss/hit transitions.
fn apply_cache_fixture(
    body_height: u32,
    header_only: u32,
) -> Result<ApplyCacheFixture, Box<dyn std::error::Error>> {
    let genesis = Network::Regtest.genesis_block();
    let mut tree = BlockTree::new();
    let genesis_id = tree.insert_node(None, genesis.header, NodeStatus::HeaderValid)?;
    let mut tip_id = genesis_id;
    let mut prev_hash = genesis.block_hash();
    let mut blocks = Vec::with_capacity(usize::try_from(body_height)?);

    for height in 1..=body_height {
        let block =
            mined_block_with_prev_hash(prev_hash, height, vec![coinbase_transaction(height)]);
        tip_id = tree.insert_node(Some(tip_id), block.header, NodeStatus::HeaderValid)?;
        prev_hash = block.block_hash();
        blocks.push(block);
    }
    for height in body_height.saturating_add(1)..=body_height.saturating_add(header_only) {
        let header = test_header(prev_hash, height);
        tip_id = tree.insert_node(Some(tip_id), header, NodeStatus::HeaderValid)?;
        prev_hash = header.compute_hash();
    }

    let chain_tip = tree.tip_handle();
    let block_tree = Arc::new(RwLock::new(tree));
    let applied_tip = Arc::new(ArcSwapOption::empty());
    let peers = Arc::new(PeerTable::new());
    let (_inbound_headers_tx, inbound_headers_rx_raw) = unbounded::<InboundHeaders>();
    let inbound_headers_rx = Arc::new(Mutex::new(inbound_headers_rx_raw));
    let (_inbound_blocks_tx, inbound_blocks_rx_raw) = unbounded::<bitcoin_rs_p2p::InboundBlock>();
    let inbound_blocks_rx = Arc::new(Mutex::new(inbound_blocks_rx_raw));
    let handles = apply_handles(Arc::clone(&chain_tip), Arc::clone(&applied_tip), block_tree);
    let sync = BlockSync::for_test(handles, peers, inbound_headers_rx, inbound_blocks_rx);
    // Apply genesis so the applied tip starts at height 0; no block bodies
    // are staged yet, leaving every round below to drive cache state.
    sync.ensure_genesis_tip();
    assert_eq!(
        applied_tip.load_full().map(|tip| tip.height),
        Some(0),
        "fixture must apply genesis before staging bodies"
    );

    Ok(ApplyCacheFixture {
        sync,
        blocks,
        applied_tip,
        chain_tip,
    })
}

fn stage_body(sync: &BlockSync, block: &Block) {
    let hash = Hash256::from_le_bytes(block.block_hash().as_bytes());
    let serialized = bytes::Bytes::from(consensus_bytes(block));
    sync.block_stager
        .lock()
        .insert(hash, None, block.clone(), serialized, Instant::now());
}

fn cache_snapshot(sync: &BlockSync) -> Option<super::ExpectedApplyCache> {
    sync.expected_apply_cache.lock().clone()
}

type SyncFixture = (
    BlockSync,
    Arc<PeerTable>,
    Arc<RwLock<BlockTree>>,
    Arc<ArcSwapOption<TipSnapshot>>,
    Vec<BlockHash>,
);

type InboundBlockSender = crossbeam_channel::Sender<bitcoin_rs_p2p::InboundBlock>;

fn sync_with_header_chain(height: u32) -> Result<SyncFixture, Box<dyn std::error::Error>> {
    // Dropping the sender mirrors the original fixture: a disconnected
    // inbound-blocks channel that never yields a block.
    let (fixture, _inbound_blocks_tx) = sync_with_header_chain_and_blocks(height)?;
    Ok(fixture)
}

fn sync_with_header_chain_and_blocks(
    height: u32,
) -> Result<(SyncFixture, InboundBlockSender), Box<dyn std::error::Error>> {
    let mut tree = BlockTree::new();
    let genesis = genesis_header();
    let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
    let mut tip_id = genesis_id;
    let mut expected = Vec::new();

    for height in 1_u32..=height {
        let parent_hash = BlockHash::from(tree.node(tip_id)?.hash);
        let header = test_header(parent_hash, height);
        tip_id = tree.insert_node(Some(tip_id), header, NodeStatus::HeaderValid)?;
        expected.push(BlockHash::from(tree.node(tip_id)?.hash));
    }

    let chain_tip = tree.tip_handle();
    let block_tree = Arc::new(RwLock::new(tree));
    let applied_tip = Arc::new(ArcSwapOption::empty());
    let peers = Arc::new(PeerTable::new());
    let (_inbound_headers_tx, inbound_headers_rx_raw) = unbounded::<InboundHeaders>();
    let inbound_headers_rx = Arc::new(Mutex::new(inbound_headers_rx_raw));
    let (inbound_blocks_tx, inbound_blocks_rx_raw) = unbounded::<bitcoin_rs_p2p::InboundBlock>();
    let inbound_blocks_rx = Arc::new(Mutex::new(inbound_blocks_rx_raw));
    let handles = apply_handles(
        Arc::clone(&chain_tip),
        Arc::clone(&applied_tip),
        Arc::clone(&block_tree),
    );
    let sync = BlockSync::for_test(
        handles,
        Arc::clone(&peers),
        inbound_headers_rx,
        inbound_blocks_rx,
    );

    Ok((
        (sync, peers, block_tree, applied_tip, expected),
        inbound_blocks_tx,
    ))
}

type MinedChainFixture = (
    BlockSync,
    Arc<PeerTable>,
    Arc<ArcSwapOption<TipSnapshot>>,
    Vec<Block>,
    InboundBlockSender,
);

/// Like [`sync_with_header_chain_and_blocks`] but with fully applicable
/// mined regtest blocks (coinbase-bearing, PoW-valid), so tests can drive
/// real apply progress through the inbound channel.
fn sync_with_mined_chain(count: u32) -> Result<MinedChainFixture, Box<dyn std::error::Error>> {
    let genesis = Network::Regtest.genesis_block();
    let mut tree = BlockTree::new();
    let mut node_id = tree.insert_node(None, genesis.header, NodeStatus::HeaderValid)?;
    let mut prev_hash = genesis.block_hash();
    let mut blocks = Vec::with_capacity(usize::try_from(count)?);
    for height in 1..=count {
        let block =
            mined_block_with_prev_hash(prev_hash, height, vec![coinbase_transaction(height)]);
        node_id = tree.insert_node(Some(node_id), block.header, NodeStatus::HeaderValid)?;
        prev_hash = block.block_hash();
        blocks.push(block);
    }

    let chain_tip = tree.tip_handle();
    let block_tree = Arc::new(RwLock::new(tree));
    let applied_tip = Arc::new(ArcSwapOption::empty());
    let peers = Arc::new(PeerTable::new());
    let (_inbound_headers_tx, inbound_headers_rx_raw) = unbounded::<InboundHeaders>();
    let inbound_headers_rx = Arc::new(Mutex::new(inbound_headers_rx_raw));
    let (inbound_blocks_tx, inbound_blocks_rx_raw) = unbounded::<bitcoin_rs_p2p::InboundBlock>();
    let inbound_blocks_rx = Arc::new(Mutex::new(inbound_blocks_rx_raw));
    let handles = apply_handles(
        Arc::clone(&chain_tip),
        Arc::clone(&applied_tip),
        Arc::clone(&block_tree),
    );
    let sync = BlockSync::for_test(
        handles,
        Arc::clone(&peers),
        inbound_headers_rx,
        inbound_blocks_rx,
    );
    // `node_id` ends as the chain tip; it only exists to thread parents.
    let _ = node_id;

    Ok((sync, peers, applied_tip, blocks, inbound_blocks_tx))
}

type WedgeFixture = (
    BlockSync,
    Arc<PeerTable>,
    Vec<BlockHash>,
    Vec<crossbeam_channel::Receiver<Message>>,
    InboundBlockSender,
);

/// The recorded-collapse construction at `install_budget` scale: eight
/// eligible peers stripe a 16-block window at per-peer fan-out cap 2
/// against a 64-block header chain; the front-stripe owner (the highest
/// peer, heights 1-2) stalls while the seven healthy peers deliver
/// heights 3..=16 into the inbound channel. After the caller's next tick
/// drains them, staged (14) + pending (2) sit exactly at the count
/// budget (16) with the apply frontier frozen behind the stall. Byte
/// budgets are unbounded so only count-denominated behavior is exercised.
fn wedge_budget(pending_timeout: Duration) -> super::SyncBudget {
    super::SyncBudget {
        max_pending_blocks: 16,
        max_pending_bytes: usize::MAX,
        max_received_blocks: 16,
        max_received_bytes: usize::MAX,
        max_peer_inflight: 16,
        fanout_peer_inflight: 2,
        min_peers_for_fanout: 8,
        getdata_batch_limit: 16,
        pending_timeout,
        ..super::default_sync_budget()
    }
}

fn staged_count_wedge(
    budget: super::SyncBudget,
) -> Result<WedgeFixture, Box<dyn std::error::Error>> {
    let ((sync, peers, block_tree, applied_tip, expected), blocks_tx) =
        sync_with_header_chain_and_blocks(64)?;
    let peer_count = budget.min_peers_for_fanout;
    install_budget(&sync, budget);
    let mut rxs = Vec::new();
    for idx in 0..peer_count {
        let addr = test_addr(9320, idx)?;
        rxs.push(connect_peer(
            &peers,
            eligible_peer(addr, 200 - i32::try_from(idx)?),
        ));
    }

    sync.tick();

    assert_applied_genesis(&applied_tip, &block_tree, &sync.handles)?;
    for (idx, rx) in rxs.iter().enumerate() {
        let Message::GetData(inventory) = rx.try_recv()? else {
            return Err(std::io::Error::other("expected a striped getdata per peer").into());
        };
        assert_eq!(
            witness_block_inventory(inventory)?,
            expected[idx * 2..(idx + 1) * 2]
        );
    }
    for height in 3..=16_u32 {
        blocks_tx.send(bitcoin_rs_p2p::InboundBlock::from_decoded(
            header_chain_block(&expected, height)?,
        ))?;
    }
    Ok((sync, peers, expected, rxs, blocks_tx))
}

/// Returns the next `getdata` inventory from `rx`, skipping header
/// traffic; fails when none is queued.
fn next_getdata(
    rx: &crossbeam_channel::Receiver<Message>,
) -> Result<Vec<Inventory>, Box<dyn std::error::Error>> {
    while let Ok(message) = rx.try_recv() {
        if let Message::GetData(inventory) = message {
            return Ok(inventory);
        }
    }
    Err(std::io::Error::other("expected a queued getdata").into())
}

/// Drains `rx`, failing on any `getdata` while ignoring header traffic.
fn assert_no_getdata(
    rx: &crossbeam_channel::Receiver<Message>,
) -> Result<(), Box<dyn std::error::Error>> {
    while let Ok(message) = rx.try_recv() {
        if matches!(message, Message::GetData(_)) {
            return Err(std::io::Error::other("unexpected getdata").into());
        }
    }
    Ok(())
}

/// Reconstructs the deliverable block body (header-only, empty `txs`)
/// for `height` of a [`sync_with_header_chain`] fixture: the block hash
/// is the header hash, so the delivery matches the fixture's tree node.
fn header_chain_block(
    expected: &[BlockHash],
    height: u32,
) -> Result<Block, Box<dyn std::error::Error>> {
    let index = usize::try_from(height.checked_sub(1).ok_or("height must be >= 1")?)?;
    let prev_blockhash = if index == 0 {
        genesis_header().compute_hash()
    } else {
        expected[index - 1]
    };
    let block = Block {
        header: test_header(prev_blockhash, height),
        txs: Vec::new(),
    };
    assert_eq!(
        block.block_hash(),
        expected[index],
        "reconstructed block must hash to the fixture's header-chain node"
    );
    Ok(block)
}

fn install_budget(sync: &BlockSync, budget: super::SyncBudget) {
    sync.install_budget(budget);
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum TestMetric {
    Counter(u64),
    Gauge(f64),
    Histogram { count: u64, sum: f64 },
}

#[derive(Clone, Debug, Default)]
struct TestRecorder {
    values: Arc<Mutex<HashMap<String, TestMetric>>>,
}

impl TestRecorder {
    fn metric_key(key: &Key) -> String {
        key.name().to_owned()
    }

    fn snapshot(&self) -> HashMap<String, TestMetric> {
        self.values.lock().clone()
    }
}

impl Recorder for TestRecorder {
    fn describe_counter(&self, _key: KeyName, _unit: Option<Unit>, _description: SharedString) {}

    fn describe_gauge(&self, _key: KeyName, _unit: Option<Unit>, _description: SharedString) {}

    fn describe_histogram(&self, _key: KeyName, _unit: Option<Unit>, _description: SharedString) {}

    fn register_counter(&self, key: &Key, _metadata: &Metadata<'_>) -> Counter {
        Counter::from_arc(Arc::new(TestCounter {
            key: Self::metric_key(key),
            recorder: self.clone(),
        }))
    }

    fn register_gauge(&self, key: &Key, _metadata: &Metadata<'_>) -> Gauge {
        Gauge::from_arc(Arc::new(TestGauge {
            key: Self::metric_key(key),
            recorder: self.clone(),
        }))
    }

    fn register_histogram(&self, key: &Key, _metadata: &Metadata<'_>) -> Histogram {
        Histogram::from_arc(Arc::new(TestHistogram {
            key: Self::metric_key(key),
            recorder: self.clone(),
        }))
    }
}

struct TestCounter {
    key: String,
    recorder: TestRecorder,
}

impl CounterFn for TestCounter {
    fn increment(&self, value: u64) {
        let mut values = self.recorder.values.lock();
        let entry = values
            .entry(self.key.clone())
            .or_insert(TestMetric::Counter(0));
        if let TestMetric::Counter(current) = entry {
            *current = current.saturating_add(value);
        }
    }

    fn absolute(&self, value: u64) {
        self.recorder
            .values
            .lock()
            .insert(self.key.clone(), TestMetric::Counter(value));
    }
}

struct TestGauge {
    key: String,
    recorder: TestRecorder,
}

impl GaugeFn for TestGauge {
    fn increment(&self, value: f64) {
        let mut values = self.recorder.values.lock();
        let entry = values
            .entry(self.key.clone())
            .or_insert(TestMetric::Gauge(0.0));
        if let TestMetric::Gauge(current) = entry {
            *current += value;
        }
    }

    fn decrement(&self, value: f64) {
        let mut values = self.recorder.values.lock();
        let entry = values
            .entry(self.key.clone())
            .or_insert(TestMetric::Gauge(0.0));
        if let TestMetric::Gauge(current) = entry {
            *current -= value;
        }
    }

    fn set(&self, value: f64) {
        self.recorder
            .values
            .lock()
            .insert(self.key.clone(), TestMetric::Gauge(value));
    }
}

struct TestHistogram {
    key: String,
    recorder: TestRecorder,
}

impl HistogramFn for TestHistogram {
    fn record(&self, value: f64) {
        let mut values = self.recorder.values.lock();
        let entry = values
            .entry(self.key.clone())
            .or_insert(TestMetric::Histogram { count: 0, sum: 0.0 });
        if let TestMetric::Histogram { count, sum } = entry {
            *count = count.saturating_add(1);
            *sum += value;
        }
    }
}

fn assert_gauge(recorder: &TestRecorder, name: &str, expected: usize) {
    let expected = super::metric_count(expected);
    assert_eq!(
        recorder.snapshot().get(name),
        Some(&TestMetric::Gauge(expected)),
        "{name} gauge must match deterministic sync pipeline state",
    );
}

fn assert_metric_absent(recorder: &TestRecorder, name: &str) {
    assert!(
        !recorder.snapshot().contains_key(name),
        "{name} metric should not be recorded"
    );
}

fn assert_histogram(recorder: &TestRecorder, name: &str) {
    match recorder.snapshot().get(name) {
        Some(TestMetric::Histogram { count, sum }) => {
            assert_ne!(
                *count, 0,
                "{name} histogram must record at least one sample"
            );
            assert!(sum.is_finite(), "{name} histogram sum must be finite");
        }
        value => panic!("{name} histogram missing or wrong type: {value:?}"),
    }
}

struct FailOnceBodyStore {
    fail_height: u32,
    failed: Mutex<bool>,
    persisted: Mutex<HashMap<u32, Vec<u8>>>,
}

impl FailOnceBodyStore {
    fn new(fail_height: u32) -> Self {
        Self {
            fail_height,
            failed: Mutex::new(false),
            persisted: Mutex::new(HashMap::new()),
        }
    }

    fn persisted_height(&self, height: u32) -> bool {
        self.persisted.lock().contains_key(&height)
    }
}

impl bitcoin_rs_storage::block_body::BlockBodyStore for FailOnceBodyStore {
    fn persist_block_body(
        &self,
        height: u32,
        _hash: Hash256,
        body: &[u8],
    ) -> Result<(), StorageError> {
        let mut failed = self.failed.lock();
        if height == self.fail_height && !*failed {
            *failed = true;
            return Err(StorageError::backend("fail-once block body store"));
        }
        drop(failed);
        self.persisted.lock().insert(height, body.to_vec());
        Ok(())
    }

    fn load_block_body(
        &self,
        height: u32,
        _hash: Hash256,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self.persisted.lock().get(&height).cloned())
    }

    fn sync(&self) -> Result<(), StorageError> {
        Ok(())
    }
}

fn witness_block_inventory(
    inventory: Vec<Inventory>,
) -> Result<Vec<BlockHash>, Box<dyn std::error::Error>> {
    inventory
        .into_iter()
        .map(|item| match item {
            // Wire seam: Inventory payloads stay bitcoin::; convert to native.
            Inventory::WitnessBlock(hash) => {
                Ok(BlockHash(Hash256::from_le_bytes(hash.as_byte_array())))
            }
            _ => Err(std::io::Error::other("expected witness block inventory").into()),
        })
        .collect()
}

#[allow(clippy::arc_with_non_send_sync)]
fn apply_handles(
    chain_tip: Arc<ArcSwapOption<TipSnapshot>>,
    applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
    block_tree: Arc<RwLock<BlockTree>>,
) -> Chainstate {
    let mempool = Arc::new(RwLock::new(Mempool::new(MempoolLimits::default())));
    let mempool_gateway = bitcoin_rs_mempool::MempoolGateway::shared(Arc::clone(&mempool));
    Chainstate::new(
        Network::Regtest,
        chain_tip,
        applied_tip,
        block_tree,
        Arc::new(UtxoSet::new()),
        Arc::new(bitcoin_rs_utxo::stats::CoinStatsListener::new(
            bitcoin_rs_utxo::stats::CoinStats::default(),
        )),
        mempool,
        mempool_gateway,
        Arc::new(crate::state::ChainEventPublisher::detached(0).0),
    )
}

/// Regtest genesis timestamp. Fixture headers must advance past it or the
/// median-time-past rule rejects them, since the median is taken over the
/// ancestors actually present in the tree.
const GENESIS_TIME: u32 = 1_296_688_602;

fn test_header(prev_blockhash: BlockHash, height: u32) -> Header {
    use bitcoin_rs_primitives::CompactTarget;
    let mut merkle = [0_u8; 32];
    merkle[..4].copy_from_slice(&height.to_le_bytes());
    let mut header = Header {
        version: 1,
        prev_blockhash,
        merkle_root: Hash256::from_le_bytes(&merkle),
        time: GENESIS_TIME.saturating_add(height),
        bits: CompactTarget::from_consensus(0x207f_ffff),
        nonce: height,
    };
    // Mine rather than hope: the fixture previously relied on nonce=height
    // happening to satisfy regtest's easy target, so any change to another
    // header field silently broke proof-of-work validation.
    while !pow_met(
        header.bits.to_consensus(),
        Hash256::from(header.compute_hash()),
    ) {
        header.nonce = header.nonce.wrapping_add(1);
    }
    header
}

fn nbits_mismatch_header(prev_blockhash: BlockHash, height: u32) -> Header {
    use bitcoin_rs_primitives::CompactTarget;
    let mut header = test_header(prev_blockhash, height);
    header.bits = CompactTarget::from_consensus(0x207f_fffe);
    for nonce in 0..=u32::MAX {
        header.nonce = nonce;
        if pow_met(
            header.bits.to_consensus(),
            Hash256::from(header.compute_hash()),
        ) {
            return header;
        }
    }
    panic!("exhausted the header nonce space while mining a regtest fixture");
}

fn far_future_header(
    prev_blockhash: BlockHash,
    height: u32,
) -> Result<Header, Box<dyn std::error::Error>> {
    let mut header = test_header(prev_blockhash, height);
    header.time = bitcoin_rs_chain::current_unix_seconds().saturating_add(3 * 60 * 60);
    for nonce in 0..=u32::MAX {
        header.nonce = nonce;
        if pow_met(
            header.bits.to_consensus(),
            Hash256::from(header.compute_hash()),
        ) {
            return Ok(header);
        }
    }
    Err(std::io::Error::other("exhausted future-header nonce space").into())
}

/// Regtest-easy compact-target `PoW` check over the hash as a 256-bit
/// little-endian integer (mirrors `chain::pow::compact_is_met_by` for the
/// >3-exponent, 3-byte-mantissa forms these fixtures mine).
fn pow_met(bits: u32, hash: Hash256) -> bool {
    let exponent = bits >> 24;
    let mantissa = bits & 0x007f_ffff;
    if exponent <= 3 || exponent > 32 || mantissa > 0x00ff_ffff {
        return false;
    }
    let bytes = hash.as_byte_array();
    let lo = usize::try_from(exponent).unwrap_or(32) - 3;
    let window =
        u32::from(bytes[lo]) | u32::from(bytes[lo + 1]) << 8 | u32::from(bytes[lo + 2]) << 16;
    window <= mantissa
        && bytes[usize::try_from(exponent).unwrap_or(32)..]
            .iter()
            .all(|&byte| byte == 0)
}

struct HeaderSyncFixture {
    genesis: Header,
    sync: BlockSync,
    inbound_headers_tx: crossbeam_channel::Sender<InboundHeaders>,
    peers: Arc<PeerTable>,
}

fn header_sync_with_genesis() -> Result<HeaderSyncFixture, Box<dyn std::error::Error>> {
    let mut tree = BlockTree::new();
    let genesis = genesis_header();
    tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
    let chain_tip = tree.tip_handle();
    let block_tree = Arc::new(RwLock::new(tree));
    let applied_tip = Arc::new(ArcSwapOption::empty());
    let peers = Arc::new(PeerTable::new());
    let (inbound_headers_tx, inbound_headers_rx_raw) = unbounded::<InboundHeaders>();
    let inbound_headers_rx = Arc::new(Mutex::new(inbound_headers_rx_raw));
    let (_inbound_blocks_tx, inbound_blocks_rx_raw) = unbounded::<bitcoin_rs_p2p::InboundBlock>();
    let inbound_blocks_rx = Arc::new(Mutex::new(inbound_blocks_rx_raw));
    let handles = apply_handles(chain_tip, applied_tip, block_tree);
    let sync = BlockSync::for_test(
        handles,
        Arc::clone(&peers),
        inbound_headers_rx,
        inbound_blocks_rx,
    );
    install_budget(
        &sync,
        super::SyncBudget {
            max_pending_blocks: 0,
            ..super::default_sync_budget()
        },
    );
    Ok(HeaderSyncFixture {
        genesis,
        sync,
        inbound_headers_tx,
        peers,
    })
}

fn genesis_header() -> Header {
    Network::Regtest.genesis_block().header
}

fn coinbase_transaction(height: u32) -> Tx {
    use bitcoin_rs_primitives::{Amount, LockTime, Script, Sequence, Witness};
    let mut script_sig = push_int(i64::from(height));
    script_sig.extend_from_slice(&push_int(1));
    Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(Txid::default(), u32::MAX),
            script_sig: Script::from_bytes(script_sig),
            sequence: Sequence::from_consensus(0xffff_ffff),
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: Script::new(),
        }],
        lock_time: LockTime::from_consensus(0),
    }
}

fn transaction(seed: u8) -> Tx {
    use bitcoin_rs_primitives::{Amount, LockTime, Script, Sequence, Witness};
    Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(
                Txid(Hash256::from_le_bytes(&[seed; 32])),
                u32::from(seed),
            ),
            script_sig: Script::new(),
            sequence: Sequence::from_consensus(0xffff_ffff),
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: Script::new(),
        }],
        lock_time: LockTime::from_consensus(0),
    }
}

fn mined_block_with_prev_hash(prev_blockhash: BlockHash, height: u32, txdata: Vec<Tx>) -> Block {
    use bitcoin_rs_primitives::CompactTarget;
    let mut block = Block {
        header: Header {
            version: 1,
            prev_blockhash,
            merkle_root: Hash256::default(),
            time: GENESIS_TIME.saturating_add(height),
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        },
        txs: txdata,
    };
    block.header.merkle_root = merkle_root(&block.txs);
    while !pow_met(
        block.header.bits.to_consensus(),
        Hash256::from(block.block_hash()),
    ) {
        block.header.nonce = block.header.nonce.saturating_add(1);
    }
    block
}

/// Consensus merkle fold: pairwise double-SHA256 over little-endian txid
/// bytes, duplicating the last leaf on odd levels.
#[allow(clippy::expect_used)]
fn merkle_root(txs: &[Tx]) -> Hash256 {
    let mut hashes: Vec<[u8; 32]> = txs.iter().map(|tx| *tx.txid().as_bytes()).collect();
    if hashes.is_empty() {
        return Hash256::default();
    }
    while hashes.len() > 1 {
        if hashes.len() % 2 == 1 {
            let last = hashes.last().expect("odd merkle level has a last leaf");
            hashes.push(*last);
        }
        hashes = hashes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                let mut buffer = [0_u8; 64];
                buffer[..32].copy_from_slice(&pair[0]);
                buffer[32..].copy_from_slice(&pair[1]);
                double_sha256(&buffer).to_le_bytes()
            })
            .collect();
    }
    let root = hashes.first().expect("merkle fold reduces to one root");
    Hash256::from_le_bytes(root)
}

fn assert_applied_genesis(
    applied_tip: &Arc<ArcSwapOption<TipSnapshot>>,
    block_tree: &Arc<RwLock<BlockTree>>,
    handles: &Chainstate,
) -> Result<(), Box<dyn std::error::Error>> {
    let genesis_hash = Network::Regtest.genesis_block_hash();
    let tip = applied_tip
        .load_full()
        .ok_or_else(|| std::io::Error::other("missing applied genesis tip"))?;
    assert_eq!(tip.height, 0);
    assert_eq!(tip.hash, genesis_hash);
    assert_eq!(block_tree.read().height_of_hash(genesis_hash), Some(0));
    assert_eq!(handles.utxo.len(), 0);
    Ok(())
}

fn current_source(peer_table: &Arc<PeerTable>, addr: SocketAddr) -> PeerSource {
    peer_table.lease(addr).map_or_else(
        || panic!("test peer {addr} must be connected"),
        |lease| lease.source(addr),
    )
}

fn register_info(peer_table: &Arc<PeerTable>, info: PeerInfo) {
    let (tx, _rx) = unbounded::<Message>();
    let lease = PeerLease::new(tx);
    peer_table.register(info.addr, lease.clone());
    peer_table.publish_info(info.addr, &lease, info);
}

fn synthetic_peer(addr: SocketAddr, start_height: i32) -> PeerInfo {
    PeerInfo {
        addr,
        version: 70_016,
        wtxid_relay: false,
        compact_block_relay: false,
        services: 0,
        user_agent: String::from("/test/"),
        start_height,
        best_known_height: start_height,
        conn_time: 0,
        inbound: true,
        addr_bind: addr,
        time_offset: 0,
        counters: alloc::sync::Arc::new(bitcoin_rs_p2p::PeerCounters::default()),
    }
}

fn eligible_peer(addr: SocketAddr, start_height: i32) -> PeerInfo {
    PeerInfo {
        // SERVICE_WITNESS (1 << 3) | NODE_NETWORK (1): native peer flags.
        services: 0b1001,
        inbound: false,
        addr_bind: addr,
        time_offset: 0,
        counters: std::sync::Arc::new(bitcoin_rs_p2p::PeerCounters::default()),
        ..synthetic_peer(addr, start_height)
    }
}

fn test_addr(base_port: usize, idx: usize) -> Result<SocketAddr, Box<dyn std::error::Error>> {
    Ok(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        u16::try_from(base_port + idx)?,
    ))
}

fn connect_peer(
    peer_table: &Arc<PeerTable>,
    info: PeerInfo,
) -> crossbeam_channel::Receiver<Message> {
    let (tx, rx) = unbounded::<Message>();
    let lease = PeerLease::new(tx);
    peer_table.register(info.addr, lease.clone());
    peer_table.publish_info(info.addr, &lease, info);
    rx
}

/// Failure-injecting undo store: clearing the in-flight marker always
/// fails, which is exactly the `MarkerStuck` fatal condition. Everything
/// else delegates to the real store it wraps.
struct DisarmFailsUndoStore {
    inner: Arc<dyn crate::apply::UndoStore>,
}

impl crate::apply::UndoStore for DisarmFailsUndoStore {
    fn persist_undo(
        &self,
        height: u32,
        hash: Hash256,
        record: &[u8],
    ) -> Result<(), bitcoin_rs_storage::StorageError> {
        self.inner.persist_undo(height, hash, record)
    }

    fn load_undo(
        &self,
        height: u32,
        hash: Hash256,
    ) -> Result<Option<Vec<u8>>, bitcoin_rs_storage::StorageError> {
        self.inner.load_undo(height, hash)
    }

    fn arm_disconnect(
        &self,
        height: u32,
        hash: Hash256,
    ) -> Result<(), bitcoin_rs_storage::StorageError> {
        self.inner.arm_disconnect(height, hash)
    }

    fn complete_disconnect(
        &self,
        _height: u32,
        _hash: Hash256,
    ) -> Result<(), bitcoin_rs_storage::StorageError> {
        // A completed rollback that cannot record itself is exactly the
        // `MarkerStuck` fatal condition.
        Err(bitcoin_rs_storage::StorageError::backend(
            "injected marker-clear failure",
        ))
    }

    fn disarm_disconnect(&self) -> Result<(), bitcoin_rs_storage::StorageError> {
        self.inner.disarm_disconnect()
    }

    fn load_disconnect_marker(
        &self,
    ) -> Result<Option<bitcoin_rs_storage::DisconnectMarker>, bitcoin_rs_storage::StorageError>
    {
        self.inner.load_disconnect_marker()
    }
}

type MaturedChain = (
    Chainstate,
    Vec<Block>,
    HashMap<Hash256, (Block, bytes::Bytes)>,
);

fn matured_chain(depth: u32) -> Result<MaturedChain, Box<dyn std::error::Error>> {
    use bitcoin_rs_primitives::{Amount, LockTime, Script, Sequence, Witness};
    let genesis = Network::Regtest.genesis_block();
    let mut tree = BlockTree::new();
    let mut parent = tree.insert_node(None, genesis.header, NodeStatus::HeaderValid)?;
    let subsidy = 5_000_000_000_u64;
    let mut prev_hash = genesis.block_hash();
    let mut blocks: Vec<Block> = Vec::new();
    for height in 1..=depth {
        let mut coinbase = coinbase_transaction(height);
        if height == 1 {
            coinbase.outputs[0].value = Amount::from_sat(subsidy);
        }
        let mut txs = vec![coinbase];
        if height == depth {
            let first_txid = blocks[0].txs[0].txid();
            txs.push(Tx {
                version: 2,
                inputs: vec![TxIn {
                    previous_output: OutPoint::new(first_txid, 0),
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
        let block = mined_block_with_prev_hash(prev_hash, height, txs);
        parent = tree.insert_node(Some(parent), block.header, NodeStatus::HeaderValid)?;
        prev_hash = block.block_hash();
        blocks.push(block);
    }
    let chain_tip = tree.tip_handle();
    let applied_tip = Arc::new(ArcSwapOption::empty());
    let handles = apply_handles(chain_tip, applied_tip, Arc::new(RwLock::new(tree)));
    handles.apply_block(&genesis)?;
    for block in &blocks {
        handles.apply_block(block)?;
    }
    let bodies: HashMap<Hash256, (Block, bytes::Bytes)> = blocks
        .iter()
        .map(|block| {
            (
                Hash256::from_le_bytes(block.block_hash().as_bytes()),
                (block.clone(), bytes::Bytes::from(consensus_bytes(block))),
            )
        })
        .collect();
    Ok((handles, blocks, bodies))
}

#[cfg(test)]
mod behavior_1;

#[cfg(test)]
mod behavior_2;

#[cfg(test)]
mod behavior_3;

#[cfg(test)]
mod behavior_4;

#[cfg(test)]
mod behavior_5;

#[cfg(test)]
mod behavior_6;

#[cfg(test)]
mod transitions_1;

#[cfg(test)]
mod transitions_2;

#[cfg(test)]
mod transitions_3;

#[cfg(test)]
mod transitions_4;

#[cfg(test)]
mod transitions_5;

#[cfg(test)]
mod transitions_6;

#[cfg(test)]
mod transitions_7;

#[cfg(test)]
mod validation_1;

#[cfg(test)]
mod persistence_1;
