use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use arc_swap::ArcSwapOption;
use bitcoin::bip152::HeaderAndShortIds;
use bitcoin::p2p::message_compact_blocks::CmpctBlock;
use bitcoin_rs_primitives::{Hash256, consensus_bytes};
use parking_lot::RwLock;

use super::{ConnectionShared, test_shared};
use crate::PeerSource;
use crate::connection::MAX_UNSOLICITED_BLOCK_FORWARDS;
use crate::sync::BlockSync;
use crate::sync::chain::SyncChain;
use crate::sync::test_support::{TestChain, mined_chain};
use crate::test_support::{connect_peer, current_source, synthetic_peer, test_addr};
use bitcoin_rs_chain::regtest_fixture;

fn genesis_body() -> bitcoin_rs_primitives::Block {
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    let bytes = bitcoin::consensus::encode::serialize(&genesis);
    bitcoin_rs_primitives::deserialize::<bitcoin_rs_primitives::Block>(&bytes)
        .expect("regtest genesis block must decode")
}

struct MinedSyncFixture {
    sync: Arc<BlockSync>,
    blocks: Vec<bitcoin_rs_primitives::Block>,
    sync_headers_tx: crossbeam_channel::Sender<crate::InboundHeaders>,
}

fn test_sync_with_mined_chain(
    peers: &Arc<crate::PeerTable>,
) -> Result<MinedSyncFixture, Box<dyn std::error::Error>> {
    let (mut tree, blocks) = mined_chain(1, 0)?;
    let chain_tip = tree.tip_handle();
    let block_tree = Arc::new(RwLock::new(tree));
    let (sync_headers_tx, sync_headers_rx) = crossbeam_channel::unbounded();
    let (sync_blocks_tx, sync_blocks_rx) = crossbeam_channel::unbounded();
    let chain: Arc<dyn SyncChain> = Arc::new(TestChain::new(
        chain_tip,
        Arc::new(ArcSwapOption::empty()),
        Arc::clone(&block_tree),
    ));
    let sync = Arc::new(BlockSync::new(
        chain,
        Arc::clone(peers),
        sync_headers_rx,
        sync_blocks_rx,
        crate::sync::syncing_ibd_latch(),
    ));
    sync_blocks_tx.send(crate::InboundBlock::from_local(blocks[0].clone()))?;
    sync.tick();
    Ok(MinedSyncFixture {
        sync,
        blocks,
        sync_headers_tx,
    })
}

#[test]
fn unsolicited_block_flood_is_bounded_per_source() -> Result<(), Box<dyn std::error::Error>> {
    let peers = Arc::new(crate::PeerTable::new());
    let MinedSyncFixture {
        sync,
        blocks,
        sync_headers_tx,
    } = test_sync_with_mined_chain(&peers)?;

    let flooded = test_addr(9780, 0)?;
    let _rx = connect_peer(&peers, synthetic_peer(flooded, 3));
    let source = current_source(&peers, flooded);
    let block2 = regtest_fixture::mined_block_with_prev_hash(
        blocks[0].block_hash(),
        2,
        vec![regtest_fixture::coinbase(2)],
    )
    .unwrap_or_else(|error| panic!("regtest fixture block: {error}"));
    sync_headers_tx.send(crate::InboundHeaders {
        headers: vec![block2.header],
        source: Some(source),
        wire_response: true,
    })?;
    sync.tick();
    assert!(
        sync.owns_body_fetch(source, Hash256::from(block2.block_hash())),
        "fixture: the window must own block 2's body for this connection"
    );

    let (headers_tx, _headers_rx) = crossbeam_channel::unbounded();
    let (blocks_tx, blocks_rx) = crossbeam_channel::unbounded();
    let mut shared = test_shared(Arc::clone(&peers), headers_tx, blocks_tx);
    shared.block_sync = Some(Arc::clone(&sync));
    let lease = peers
        .lease(flooded)
        .ok_or("flood connection must be registered")?;
    let unrelated = genesis_body();

    for _ in 0..=MAX_UNSOLICITED_BLOCK_FORWARDS {
        shared.send_block(
            &lease,
            flooded,
            bitcoin_rs_primitives::BlockPayload::from_local(unrelated.clone()),
        );
    }
    assert_eq!(
        blocks_rx.len(),
        MAX_UNSOLICITED_BLOCK_FORWARDS,
        "one connection may not exceed its own unsolicited forwarding bound"
    );

    shared.send_block(
        &lease,
        flooded,
        bitcoin_rs_primitives::BlockPayload::from_local(block2),
    );
    assert_eq!(
        blocks_rx.len(),
        MAX_UNSOLICITED_BLOCK_FORWARDS + 1,
        "a delivery the window owns is never dropped for the unsolicited bound"
    );

    let other: crate::PeerRemote = test_addr(9781, 0)?;
    let _other_rx = connect_peer(&peers, synthetic_peer(other, 3));
    let other_lease = peers
        .lease(other)
        .ok_or("second connection must be registered")?;
    shared.send_block(
        &other_lease,
        other,
        bitcoin_rs_primitives::BlockPayload::from_local(unrelated.clone()),
    );
    assert_eq!(
        blocks_rx.len(),
        MAX_UNSOLICITED_BLOCK_FORWARDS + 2,
        "the bound is one connection's share of the channel, not a global cap"
    );

    while blocks_rx.try_recv().is_ok() {}
    shared.send_block(
        &lease,
        flooded,
        bitcoin_rs_primitives::BlockPayload::from_local(unrelated),
    );
    assert_eq!(
        blocks_rx.len(),
        1,
        "a forwarding slot returns once sync has taken the body"
    );
    Ok(())
}

struct ScanCounter(std::sync::atomic::AtomicUsize);

impl crate::compact_blocks::CompactBlockHints for ScanCounter {
    fn for_each_identity(
        &self,
        _f: &mut dyn FnMut(bitcoin_rs_primitives::Txid, bitcoin_rs_primitives::Wtxid),
    ) {
        self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    fn get_tx_by_txid(
        &self,
        _txid: bitcoin_rs_primitives::Txid,
    ) -> Option<bitcoin_rs_primitives::Tx> {
        None
    }

    fn get_tx_by_wtxid(
        &self,
        _wtxid: bitcoin_rs_primitives::Wtxid,
    ) -> Option<bitcoin_rs_primitives::Tx> {
        None
    }
}

struct CompactTestFixture {
    sync: Arc<BlockSync>,
    blocks: Vec<bitcoin_rs_primitives::Block>,
    addr: crate::PeerRemote,
    lease: crate::PeerLease,
    source: PeerSource,
    other_source: PeerSource,
    headers_rx: crossbeam_channel::Receiver<crate::InboundHeaders>,
    blocks_rx: crossbeam_channel::Receiver<crate::InboundBlock>,
    shared: ConnectionShared,
}

fn test_sync_with_applied_chain(
    peers: &Arc<crate::PeerTable>,
) -> Result<CompactTestFixture, Box<dyn std::error::Error>> {
    let (mut tree, blocks) = mined_chain(2, 0)?;
    let chain_tip = tree.tip_handle();
    let applied_tip = Arc::new(ArcSwapOption::new(chain_tip.load_full()));
    let chain: Arc<dyn SyncChain> = Arc::new(TestChain::new(
        chain_tip,
        applied_tip,
        Arc::new(RwLock::new(tree)),
    ));
    let sync = Arc::new(BlockSync::new(
        chain,
        Arc::clone(peers),
        crossbeam_channel::unbounded().1,
        crossbeam_channel::unbounded().1,
        crate::sync::syncing_ibd_latch(),
    ));
    let addr = test_addr(9782, 0)?;
    let _outbound = connect_peer(peers, synthetic_peer(addr, 3));
    let lease = peers.lease(addr).ok_or("peer must be registered")?;
    let source = lease.source(addr.endpoint());
    let other_addr = test_addr(9783, 0)?;
    let _other = connect_peer(peers, synthetic_peer(other_addr, 3));
    let other_source = peers
        .lease(other_addr)
        .ok_or("second peer must be registered")?
        .source(other_addr.endpoint());
    let (headers_tx, headers_rx) = crossbeam_channel::unbounded();
    let (blocks_tx, blocks_rx) = crossbeam_channel::unbounded();
    let mut shared = test_shared(Arc::clone(peers), headers_tx, blocks_tx);
    shared.block_sync = Some(Arc::clone(&sync));
    Ok(CompactTestFixture {
        sync,
        blocks,
        addr,
        lease,
        source,
        other_source,
        headers_rx,
        blocks_rx,
        shared,
    })
}

fn deliver_compact_block(
    block: &bitcoin_rs_primitives::Block,
    reconstruction: &mut crate::compact_blocks::Reconstruction,
    hints: &ScanCounter,
    lease: &crate::PeerLease,
    addr: crate::PeerRemote,
    shared: &ConnectionShared,
) -> Result<(), Box<dyn std::error::Error>> {
    let block: bitcoin::Block = bitcoin::consensus::encode::deserialize(&consensus_bytes(block))?;
    let message = crate::Message::CmpctBlock(CmpctBlock {
        compact_block: HeaderAndShortIds::from_block(&block, 7, 2, &[]).expect("compact block"),
    });
    let reply =
        super::reply_bound(&message, false).and_then(|bound| lease.try_reserve_reply(bound).ok());
    let sink = super::ProductionSink::new(lease, reply);
    super::process_compact_wire_message(
        &message,
        reconstruction,
        Some(2),
        Some(hints),
        &sink,
        addr,
        shared,
    );
    Ok(())
}

#[test]
fn compact_reconstruction_requires_an_earning_header() -> Result<(), Box<dyn std::error::Error>> {
    let peers = Arc::new(crate::PeerTable::new());
    let fixture = test_sync_with_applied_chain(&peers)?;
    let sync = fixture.sync;
    let blocks = fixture.blocks;
    let addr = fixture.addr;
    let lease = fixture.lease;
    let source = fixture.source;
    let other_source = fixture.other_source;
    let headers_rx = fixture.headers_rx;
    let blocks_rx = fixture.blocks_rx;
    let shared = fixture.shared;

    let hints = ScanCounter(AtomicUsize::new(0));
    let mut reconstruction = crate::compact_blocks::Reconstruction::new();
    let mut deliver = |block: &bitcoin_rs_primitives::Block| {
        deliver_compact_block(block, &mut reconstruction, &hints, &lease, addr, &shared)
    };
    let scans = || hints.0.load(Ordering::Relaxed);

    let assert_reconstructed = |expected_scans: usize, expected_blocks: usize, message: &str| {
        assert_eq!(scans(), expected_scans, "{message}");
        assert_eq!(blocks_rx.len(), expected_blocks, "{message}");
    };
    let tip = blocks.last().ok_or("chain has a tip")?;
    let next = |height| {
        regtest_fixture::mined_block_with_prev_hash(
            tip.block_hash(),
            height,
            vec![regtest_fixture::coinbase(height)],
        )
    };

    let mut no_work = next(3)?;
    no_work.header.bits = bitcoin_rs_primitives::CompactTarget::from_consensus(0x1d00_ffff);
    deliver(&no_work)?;

    let orphan = regtest_fixture::mined_block_with_prev_hash(
        no_work.header.compute_hash(),
        4,
        vec![regtest_fixture::coinbase(4)],
    )?;
    deliver(&orphan)?;

    let replayed = blocks.first().ok_or("chain has block 1")?;
    deliver(replayed)?;
    assert_reconstructed(0, 0, "no rejected header reaches the mempool");
    for _ in 0..3 {
        let announced = headers_rx.try_recv()?;
        assert_eq!(announced.headers.len(), 1, "each header is still announced");
    }

    assert!(sync.enqueue_owned_body_fetch(
        other_source,
        Hash256::from(replayed.block_hash()),
        || true,
    ));
    deliver(replayed)?;
    assert_reconstructed(0, 0, "ownership is by exact connection");
    assert_eq!(headers_rx.try_recv()?.headers.len(), 1);

    assert!(sync.enqueue_owned_body_fetch(source, Hash256::from(replayed.block_hash()), || true,));
    deliver(replayed)?;
    assert_reconstructed(1, 1, "this connection owns the replayed body fetch");

    let extending = next(3)?;
    deliver(&extending)?;
    assert_reconstructed(2, 2, "an extending block reconstructs without a request");

    deliver(&extending)?;
    assert_reconstructed(2, 2, "a repeat never rescans the mempool");
    Ok(())
}
