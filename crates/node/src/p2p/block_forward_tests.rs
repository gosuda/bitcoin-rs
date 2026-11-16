use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use arc_swap::ArcSwapOption;
use bitcoin::bip152::HeaderAndShortIds;
use bitcoin::p2p::message_compact_blocks::CmpctBlock;
use bitcoin_rs_consensus::primitives::{Hash256, consensus_bytes};
use parking_lot::RwLock;

use crate::p2p::sync::BlockSync;
use crate::p2p::sync::chain::SyncChain;
use crate::p2p::sync::test_support::{TestChain, mined_chain};
use crate::test_support::{TestError, TestResult};
use bitcoin_rs_execution::chain::regtest_fixture;
use bitcoin_rs_wire::PeerSource;
use bitcoin_rs_wire::connection::MAX_UNSOLICITED_BLOCK_FORWARDS;
use bitcoin_rs_wire::listener::{ConnectionShared, test_shared};
use bitcoin_rs_wire::test_support::{connect_peer, current_source, synthetic_peer, test_addr};

fn genesis_body() -> bitcoin_rs_consensus::primitives::Block {
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    let bytes = bitcoin::consensus::encode::serialize(&genesis);
    bitcoin_rs_consensus::primitives::deserialize::<bitcoin_rs_consensus::primitives::Block>(&bytes)
        .expect("regtest genesis block must decode")
}

struct MinedSyncFixture {
    sync: Arc<BlockSync>,
    blocks: Vec<bitcoin_rs_consensus::primitives::Block>,
    sync_headers_tx: crossbeam_channel::Sender<bitcoin_rs_wire::InboundHeaders>,
}

fn test_sync_with_mined_chain(
    peers: &Arc<bitcoin_rs_wire::PeerTable>,
) -> Result<MinedSyncFixture, TestError> {
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
        crate::p2p::sync::syncing_ibd_latch(),
    ));
    sync_blocks_tx.send(bitcoin_rs_wire::InboundBlock::from_local(blocks[0].clone()))?;
    sync.tick();
    Ok(MinedSyncFixture {
        sync,
        blocks,
        sync_headers_tx,
    })
}

#[test]
fn unsolicited_block_flood_is_bounded_per_source() -> TestResult {
    let peers = Arc::new(bitcoin_rs_wire::PeerTable::new());
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
    sync_headers_tx.send(bitcoin_rs_wire::InboundHeaders {
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
    shared.block_sync = Some(sync.clone() as Arc<dyn bitcoin_rs_wire::listener::BlockSyncObserver>);
    let lease = peers
        .lease(flooded)
        .ok_or("flood connection must be registered")?;
    let unrelated = genesis_body();

    for _ in 0..=MAX_UNSOLICITED_BLOCK_FORWARDS {
        shared.send_block(
            &lease,
            flooded,
            bitcoin_rs_consensus::primitives::BlockImage::from_local(unrelated.clone()),
            None,
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
        bitcoin_rs_consensus::primitives::BlockImage::from_local(block2),
        None,
    );
    assert_eq!(
        blocks_rx.len(),
        MAX_UNSOLICITED_BLOCK_FORWARDS + 1,
        "a delivery the window owns is never dropped for the unsolicited bound"
    );

    let other: bitcoin_rs_wire::PeerRemote = test_addr(9781, 0)?;
    let _other_rx = connect_peer(&peers, synthetic_peer(other, 3));
    let other_lease = peers
        .lease(other)
        .ok_or("second connection must be registered")?;
    shared.send_block(
        &other_lease,
        other,
        bitcoin_rs_consensus::primitives::BlockImage::from_local(unrelated.clone()),
        None,
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
        bitcoin_rs_consensus::primitives::BlockImage::from_local(unrelated),
        None,
    );
    assert_eq!(
        blocks_rx.len(),
        1,
        "a forwarding slot returns once sync has taken the body"
    );
    Ok(())
}

struct ScanCounter(std::sync::atomic::AtomicUsize);

impl bitcoin_rs_wire::compact_blocks::CompactBlockHints for ScanCounter {
    fn for_each_identity(
        &self,
        _f: &mut dyn FnMut(
            bitcoin_rs_consensus::primitives::Txid,
            bitcoin_rs_consensus::primitives::Wtxid,
        ),
    ) {
        self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    fn get_tx_by_txid(
        &self,
        _txid: bitcoin_rs_consensus::primitives::Txid,
    ) -> Option<bitcoin_rs_consensus::primitives::Tx> {
        None
    }

    fn get_tx_by_wtxid(
        &self,
        _wtxid: bitcoin_rs_consensus::primitives::Wtxid,
    ) -> Option<bitcoin_rs_consensus::primitives::Tx> {
        None
    }
}

struct CompactTestFixture {
    sync: Arc<BlockSync>,
    blocks: Vec<bitcoin_rs_consensus::primitives::Block>,
    addr: bitcoin_rs_wire::PeerRemote,
    lease: bitcoin_rs_wire::PeerLease,
    source: PeerSource,
    other_source: PeerSource,
    headers_rx: crossbeam_channel::Receiver<bitcoin_rs_wire::InboundHeaders>,
    blocks_rx: crossbeam_channel::Receiver<bitcoin_rs_wire::InboundBlock>,
    shared: ConnectionShared,
    _outbound: [bitcoin_rs_wire::test_support::MessageReceiver; 2],
}

fn test_sync_with_applied_chain(
    peers: &Arc<bitcoin_rs_wire::PeerTable>,
) -> Result<CompactTestFixture, TestError> {
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
        crate::p2p::sync::syncing_ibd_latch(),
    ));
    let addr = test_addr(9782, 0)?;
    let outbound = connect_peer(peers, synthetic_peer(addr, 3));
    let lease = peers.lease(addr).ok_or("peer must be registered")?;
    let source = lease.source(addr.endpoint());
    let other_addr = test_addr(9783, 0)?;
    let other = connect_peer(peers, synthetic_peer(other_addr, 3));
    let other_source = peers
        .lease(other_addr)
        .ok_or("second peer must be registered")?
        .source(other_addr.endpoint());
    let (headers_tx, headers_rx) = crossbeam_channel::unbounded();
    let (blocks_tx, blocks_rx) = crossbeam_channel::unbounded();
    let mut shared = test_shared(Arc::clone(peers), headers_tx, blocks_tx);
    shared.block_sync = Some(sync.clone() as Arc<dyn bitcoin_rs_wire::listener::BlockSyncObserver>);
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
        _outbound: [outbound, other],
    })
}

fn deliver_compact_block(
    block: &bitcoin_rs_consensus::primitives::Block,
    reconstruction: &mut bitcoin_rs_wire::compact_blocks::Reconstruction,
    hints: &ScanCounter,
    lease: &bitcoin_rs_wire::PeerLease,
    addr: bitcoin_rs_wire::PeerRemote,
    shared: &ConnectionShared,
) -> Result<(), TestError> {
    let block: bitcoin::Block = bitcoin::consensus::encode::deserialize(&consensus_bytes(block))?;
    let message = crate::p2p::Message::CmpctBlock(CmpctBlock {
        compact_block: HeaderAndShortIds::from_block(&block, 7, 2, &[]).expect("compact block"),
    });
    let reply = bitcoin_rs_wire::listener::reply_bound(&message, false)
        .and_then(|bound| lease.try_reserve_reply(bound).ok());
    let sink = bitcoin_rs_wire::listener::ProductionSink::new(lease, reply);
    bitcoin_rs_wire::listener::process_compact_wire_message(
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
fn compact_reconstruction_requires_an_earning_header() -> TestResult {
    let peers = Arc::new(bitcoin_rs_wire::PeerTable::new());
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
    let mut reconstruction = bitcoin_rs_wire::compact_blocks::Reconstruction::new();
    let mut deliver = |block: &bitcoin_rs_consensus::primitives::Block| {
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
    no_work.header.bits =
        bitcoin_rs_consensus::primitives::CompactTarget::from_consensus(0x1d00_ffff);
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

// BUD-01, BUD-06
#[test]
fn wire_and_compact_receipts_keep_their_accounting_through_staging() -> TestResult {
    use bitcoin_rs_consensus::primitives::BlockImage;
    use bitcoin_rs_storage::budget::BudgetOwner;
    use bitcoin_rs_wire::inbound::block_memory::BlockMemory;

    for compact in [false, true] {
        let peers = Arc::new(bitcoin_rs_wire::PeerTable::new());
        let mut fixture = test_sync_with_applied_chain(&peers)?;
        let tip = fixture.blocks.last().ok_or("chain has a tip")?;
        let block = regtest_fixture::mined_block_with_prev_hash(
            tip.block_hash(),
            3,
            vec![regtest_fixture::coinbase(3)],
        )?;
        let encoded = bytes::Bytes::from(consensus_bytes(&block));
        let expected_image = BlockImage::from_raw(encoded.clone())?;
        let encoded_bytes = expected_image.bytes().len();
        let decoded_bytes = expected_image.retained_heap_bytes();
        let hash = Hash256::from(expected_image.block_hash());
        drop(expected_image);
        let budget = Arc::new(crate::budget::NodeBudget::from_chainstate_cache_budget(
            bitcoin_rs_storage::split_chainstate_cache_budget(64 * 1024 * 1024),
            4,
        ));
        let memory = Arc::new(BlockMemory::new(Arc::new(
            crate::budget::BudgetedIngressLedger::new(Arc::clone(&budget)),
        )));
        let held = memory.reserve(37, || false)?;
        let prior_image = budget.charged_bytes(BudgetOwner::StagedImages);
        let prior_receive = budget.charged_bytes(BudgetOwner::PeerReceive);
        let prior_total = budget.total_committed();
        fixture.shared = ConnectionShared::new(
            Arc::clone(&peers),
            bitcoin_rs_wire::BannedReader::fixture_empty(),
            Arc::clone(&fixture.shared.activity),
            fixture.shared.session_cancel.clone(),
            None,
            fixture.shared.magic,
            fixture.shared.headers_tx.clone(),
            fixture.shared.blocks_tx.clone(),
            None,
            None,
            bitcoin_rs_wire::listener::ListenerExtras {
                block_sync: fixture.shared.block_sync.clone(),
                block_memory: Some(memory),
                ..Default::default()
            },
        );

        if compact {
            deliver_compact_block(
                &block,
                &mut bitcoin_rs_wire::compact_blocks::Reconstruction::new(),
                &ScanCounter(AtomicUsize::new(0)),
                &fixture.lease,
                fixture.addr,
                &fixture.shared,
            )?;
        } else {
            let mut frame = Vec::new();
            bitcoin_rs_wire::wire::write_message(
                &mut frame,
                fixture.shared.magic,
                &bitcoin_rs_wire::Message::BlockBytes(encoded),
            )?;
            let stream = std::io::Cursor::new(frame);
            let mut peer = bitcoin_rs_wire::Peer::new(stream, fixture.shared.magic);
            peer.state = bitcoin_rs_wire::PeerState::Ready;
            match bitcoin_rs_wire::listener::run_message_loop(
                &mut peer,
                fixture.addr,
                &fixture.lease,
                &fixture.shared,
                None,
            ) {
                Err(bitcoin_rs_wire::PeerError::Io(error))
                    if error.kind() == std::io::ErrorKind::UnexpectedEof => {}
                Err(error) => return Err(error.into()),
                Ok(()) => return Err(TestError::ExpectationFailed("wire fixture must reach EOF")),
            }
        }
        let mut inbound = fixture.blocks_rx.try_recv()?;
        assert_eq!(inbound.payload().block_hash().0, hash);
        assert_eq!(inbound.source, Some(fixture.source));
        assert_eq!(fixture.headers_rx.try_recv()?.headers, vec![block.header]);
        let raw_charge = budget.charged_bytes(BudgetOwner::PeerReceive) - prior_receive;
        assert_eq!(raw_charge, 0);
        let expected_receipt = encoded_bytes + decoded_bytes;
        let expected_charge = u64::try_from(expected_receipt)?;
        assert_eq!(
            budget.charged_bytes(BudgetOwner::StagedImages),
            prior_image + expected_charge
        );
        assert_eq!(
            budget.total_committed(),
            prior_total + raw_charge + expected_charge
        );
        let credit = inbound.memory_credit.take().ok_or("wire image receipt")?;
        let payload = inbound.into_payload();
        let mut stager = crate::p2p::block_stager::BlockStager::new(
            crate::p2p::download_window::policy::default_sync_budget(
                bitcoin_rs_consensus::primitives::Network::Regtest,
            ),
        );
        let staged = stager.insert_with_credit(
            hash,
            Some(hash),
            payload,
            Some(fixture.source),
            std::time::Instant::now(),
            Some(credit),
        );
        assert!(matches!(
            staged,
            crate::p2p::block_stager::StagedBlock::Memory { bytes, ref dropped }
                if bytes == encoded_bytes && dropped.is_empty()
        ));
        assert!(stager.contains(&hash));
        assert_eq!(stager.received_bytes(), encoded_bytes);
        assert_eq!(stager.decoded_bytes(), decoded_bytes);
        assert_eq!(
            budget.charged_bytes(BudgetOwner::StagedImages),
            prior_image + expected_charge
        );
        assert_eq!(
            budget.charged_bytes(BudgetOwner::PeerReceive),
            prior_receive + raw_charge
        );
        assert_eq!(
            budget.total_committed(),
            prior_total + raw_charge + expected_charge
        );
        assert!(stager.discard(&hash));
        assert_eq!(stager.received_len(), 0);
        assert_eq!(stager.received_bytes(), 0);
        assert_eq!(stager.decoded_bytes(), 0);
        assert_eq!(budget.charged_bytes(BudgetOwner::StagedImages), prior_image);
        assert_eq!(
            budget.charged_bytes(BudgetOwner::PeerReceive),
            prior_receive
        );
        assert_eq!(budget.total_committed(), prior_total);
        drop(held);
        assert_eq!(budget.total_committed(), 0);
    }
    Ok(())
}
