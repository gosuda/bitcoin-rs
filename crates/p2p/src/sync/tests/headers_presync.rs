//! Header-presync admission gating over the real headers drain.

use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;

use super::behavior_5::deliver_headers;
use super::behavior_5::next_locator;
use bitcoin_rs_primitives::Hash256;

use super::super::SyncBudget;
use super::super::default_sync_budget;
use super::super::headers_presync::HeadersSyncPhase;
use super::super::headers_presync::HeadersSyncState;
use super::*;
use crate::dispatch::MAX_HEADERS_RESPONSE;

/// The wire page size a full `headers` message must fill to keep a
/// download-twice sync in its collection phase.
const PAGE: usize = MAX_HEADERS_RESPONSE;

/// Work units one regtest-easy header mints (measured, not assumed: see
/// the assertion in the first test).
const WORK_PER_HEADER: u64 = 2;

/// Mines one regtest-easy fixture header.
fn mine_header(prev_blockhash: BlockHash, height: u32) -> Header {
    regtest_fixture::mined_regtest_header(prev_blockhash, height).or_fail("regtest fixture header")
}

/// One regtest-easy header with the height salted into its merkle root, the
/// shape the presync commitment tests vary; grinds at the declared target.
fn test_header(prev_blockhash: BlockHash, height: u32) -> Header {
    use bitcoin_rs_primitives::CompactTarget;
    let mut merkle = [0_u8; 32];
    merkle[..4].copy_from_slice(&height.to_le_bytes());
    let mut header = Header {
        version: 4,
        prev_blockhash,
        merkle_root: Hash256::from_le_bytes(&merkle),
        time: regtest_fixture::genesis_time().saturating_add(height),
        bits: CompactTarget::from_consensus(regtest_fixture::REGTEST_BITS),
        nonce: 0,
    };
    regtest_fixture::mine_header_to_declared_target(&mut header).or_fail("regtest fixture header");
    header
}

/// Mines a regtest-easy chain of `len` headers on `fork`, starting at
/// height `fork_height + 1`.
fn chain_on(fork: &Header, fork_height: u32, len: usize) -> Vec<Header> {
    let mut headers = Vec::with_capacity(len);
    let mut prev = fork.compute_hash();
    for index in 0..len {
        let offset = u32::try_from(index).unwrap_or(u32::MAX);
        let header = mine_header(prev, fork_height + offset + 1);
        prev = header.compute_hash();
        headers.push(header);
    }
    headers
}

/// The total proof-of-work a fixture chain carries.
fn chain_work(headers: &[Header]) -> ChainWork {
    headers.iter().fold(ChainWork::ZERO, |total, header| {
        total + bitcoin_rs_chain::block_work(header)
    })
}

/// One presync fixture: its fork header, the executor, its inbound-header
/// channel, and its peer table.
type PresyncFixture = (
    Header,
    BlockSync,
    crossbeam_channel::Sender<InboundHeaders>,
    Arc<PeerTable>,
);

/// A fixture whose committed-work floor is caller-chosen, draining through
/// the real header path.
fn presync_fixture(minimum_work: ChainWork) -> Result<PresyncFixture, Box<dyn std::error::Error>> {
    let mut tree = BlockTree::new();
    let genesis = genesis_header();
    tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
    let harness =
        SyncHarness::with_chain_work(tree, crate::sync::syncing_ibd_latch(), minimum_work);
    install_budget(
        &harness.sync,
        SyncBudget {
            max_pending_blocks: 0,
            ..default_sync_budget(Network::Regtest)
        },
    );
    Ok((
        genesis,
        harness.sync,
        harness.inbound_headers_tx,
        harness.peers,
    ))
}

/// A registered connection with a message sink.
fn connect(
    peers: &Arc<PeerTable>,
    port: u16,
    start_height: i32,
) -> (SocketAddr, PeerLease, crossbeam_channel::Receiver<Message>) {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    let (tx, rx) = unbounded::<Message>();
    let lease = PeerLease::new(tx);
    peers.register(addr, lease.clone());
    peers.publish_info(addr, &lease, synthetic_peer(addr, start_height));
    (addr, lease, rx)
}

/// The number of nodes the block tree holds, so "nothing was admitted" is
/// a count, not a feeling: header admission inserts `HeaderValid` nodes and
/// never moves the applied tip.
fn tree_node_count(sync: &BlockSync) -> usize {
    sync.chain.block_tree().len()
}

/// The sync state a connection currently owns, if any.
fn with_sync_state<T>(
    sync: &BlockSync,
    source: PeerSource,
    read: impl FnOnce(&HeadersSyncState) -> T,
) -> Option<T> {
    sync.scheduler.lock().headers_sync.get(&source).map(read)
}

fn sync_phase(sync: &BlockSync, source: PeerSource) -> Option<HeadersSyncPhase> {
    with_sync_state(sync, source, HeadersSyncState::phase)
}

#[test]
fn low_work_headers_do_not_reach_block_tree() -> TestResult {
    let floor = ChainWork::from(WORK_PER_HEADER * u64::try_from(4 * PAGE).unwrap_or(u64::MAX));
    let (genesis, sync, inbound_headers_tx, peers) = presync_fixture(floor)?;
    let (addr, lease, rx) = connect(&peers, 9701, 100_000);
    let source = current_source(&peers, addr);
    sync.tick();
    assert!(matches!(rx.try_recv()?, Message::GetHeaders(_)));

    let chain = chain_on(&genesis, 0, 2 * PAGE + 500);
    assert_eq!(
        bitcoin_rs_chain::block_work(&chain[0]),
        ChainWork::from(WORK_PER_HEADER),
        "the fixture's work-per-header constant must hold"
    );
    assert!(
        chain_work(&chain) < floor,
        "the fixture chain must stay below the assumed-work floor"
    );
    deliver_headers(&inbound_headers_tx, chain[..PAGE].to_vec(), source)?;
    sync.tick();

    assert_eq!(
        tree_node_count(&sync),
        1,
        "a full page below the floor must not reach the tree"
    );
    let locator = next_locator(&rx)
        .ok_or_else(|| std::io::Error::other("the presync continuation getheaders was not sent"))?;
    assert_eq!(
        locator.first().copied(),
        Some(Hash256::from(chain[PAGE - 1].compute_hash()).to_le_bytes()),
        "the continuation must resume from the collected cursor"
    );

    deliver_headers(&inbound_headers_tx, chain[PAGE..2 * PAGE].to_vec(), source)?;
    sync.tick();

    assert_eq!(
        tree_node_count(&sync),
        1,
        "the continuation page must not reach the tree either"
    );
    assert_eq!(
        sync_phase(&sync, source),
        Some(HeadersSyncPhase::Presync),
        "a live collection must keep the state"
    );
    let cursor = with_sync_state(&sync, source, |state| state.next_locator()[0].to_le_bytes());
    assert_eq!(
        cursor,
        Some(Hash256::from(chain[2 * PAGE - 1].compute_hash()).to_le_bytes()),
        "the second page must extend the same state's cursor"
    );
    assert!(
        !lease.is_cancelled() && peers.is_connected(addr),
        "collecting a low-work chain must not blame the peer"
    );
    Ok(())
}

#[test]
fn sufficient_work_chain_syncs_presync_then_redownload() -> TestResult {
    // A chain one page plus a tail long, with the floor on its last
    // header: the first page's own claimed work stays below the floor, so
    // it collects under presync; the tail page carries the cumulative work
    // over it and the crossing commits the sync to its second pass.
    let chain = chain_on(&genesis_header(), 0, PAGE + 500);
    let threshold = chain_work(&chain);
    let (genesis, sync, inbound_headers_tx, peers) = presync_fixture(threshold)?;
    let (addr, _lease, rx) = connect(&peers, 9702, 100_000);
    let source = current_source(&peers, addr);
    sync.tick();
    assert!(matches!(rx.try_recv()?, Message::GetHeaders(_)));

    deliver_headers(&inbound_headers_tx, chain[..PAGE].to_vec(), source)?;
    sync.tick();
    assert_eq!(
        sync_phase(&sync, source),
        Some(HeadersSyncPhase::Presync),
        "a page whose own claimed work is below the floor collects"
    );
    assert_eq!(
        next_locator(&rx).map(|locator| locator.first().copied()),
        Some(Some(
            Hash256::from(chain[PAGE - 1].compute_hash()).to_le_bytes()
        )),
        "presync must request the continuation from the collected tip",
    );

    deliver_headers(&inbound_headers_tx, chain[PAGE..].to_vec(), source)?;
    sync.tick();

    assert_eq!(
        sync_phase(&sync, source),
        Some(HeadersSyncPhase::Redownload),
        "crossing must flip the sync to its second pass"
    );
    assert_eq!(
        tree_node_count(&sync),
        1,
        "crossing the floor must not admit the collected pass"
    );
    assert_eq!(
        next_locator(&rx).map(|locator| locator.first().copied()),
        Some(Some(Hash256::from(genesis.compute_hash()).to_le_bytes())),
        "the second pass must be requested on the wire from the fork point",
    );
    assert_eq!(
        with_sync_state(&sync, source, |state| state.next_locator()[0]),
        Some(Hash256::from(genesis.compute_hash())),
        "the second pass must restart at the fork point"
    );

    let chain_last = chain[PAGE + 500 - 1].compute_hash();
    deliver_headers(&inbound_headers_tx, chain[..PAGE].to_vec(), source)?;
    sync.tick();
    deliver_headers(&inbound_headers_tx, chain[PAGE..].to_vec(), source)?;
    sync.tick();
    let tree = sync.chain.block_tree();
    assert_eq!(
        tree.height_of_hash(Hash256::from(chain_last)),
        Some(u32::try_from(PAGE + 500).unwrap_or(u32::MAX)),
        "the committed replay must admit the whole chain in wire order (len {})",
        tree.len(),
    );
    drop(tree);
    assert_eq!(
        sync_phase(&sync, source),
        None,
        "a spent sync state must be retired"
    );
    Ok(())
}

#[test]
fn a_substituted_redownload_header_disconnects_the_connection() -> TestResult {
    // A page plus 500 headers whose floor crosses on the last of them:
    // the whole chain is committed at once and the replay restarts at the
    // fork point.
    let chain = chain_on(&genesis_header(), 0, PAGE + 500);
    let threshold = chain_work(&chain);
    let (_genesis, sync, inbound_headers_tx, peers) = presync_fixture(threshold)?;
    let (addr, lease, rx) = connect(&peers, 9703, 100_000);
    let source = current_source(&peers, addr);
    sync.tick();
    assert!(matches!(rx.try_recv()?, Message::GetHeaders(_)));

    deliver_headers(&inbound_headers_tx, chain[..PAGE].to_vec(), source)?;
    sync.tick();
    deliver_headers(&inbound_headers_tx, chain[PAGE..].to_vec(), source)?;
    sync.tick();
    assert_eq!(
        sync_phase(&sync, source),
        Some(HeadersSyncPhase::Redownload),
        "the fixture must reach its second pass"
    );

    let Some(commitment_height) =
        with_sync_state(&sync, source, |state| state.first_commitment_height(2))
    else {
        unreachable!("the sync state is live");
    };
    let chain_len = chain.len();
    let commitment_index = usize::try_from(commitment_height).unwrap_or(usize::MAX);
    assert!(commitment_index <= chain_len);
    let original_hash = chain[commitment_index - 1].compute_hash();
    let mut rogue = test_header(
        chain[commitment_index - 2].compute_hash(),
        commitment_height,
    );
    let original_bit = with_sync_state(&sync, source, |state| {
        state.commitment_bit(Hash256::from(original_hash))
    })
    .unwrap_or_else(|| unreachable!("the sync state is live"));
    loop {
        let hash = Hash256::from(rogue.compute_hash());
        let bit = with_sync_state(&sync, source, |state| state.commitment_bit(hash))
            .unwrap_or_else(|| unreachable!("the sync state is live"));
        if hash != Hash256::from(original_hash)
            && bit != original_bit
            && bitcoin_rs_chain::compact_is_met_by(rogue.bits, hash)
        {
            break;
        }
        rogue.nonce = rogue.nonce.wrapping_add(1);
    }
    let mut substituted = chain;
    substituted[commitment_index - 1] = rogue;
    for index in commitment_index..chain_len {
        let mut header = substituted[index];
        header.prev_blockhash = substituted[index - 1].compute_hash();
        while !bitcoin_rs_chain::compact_is_met_by(
            header.bits,
            Hash256::from(header.compute_hash()),
        ) {
            header.nonce = header.nonce.wrapping_add(1);
        }
        substituted[index] = header;
    }

    deliver_headers(&inbound_headers_tx, substituted, source)?;
    sync.tick();

    assert!(
        lease.is_cancelled() || !peers.is_connected(addr),
        "a salted-commitment divergence must cost the connection its lease"
    );
    assert_eq!(
        tree_node_count(&sync),
        1,
        "the mismatching batch must admit nothing"
    );
    assert_eq!(
        sync_phase(&sync, source),
        None,
        "the punished sync state must be retired"
    );
    Ok(())
}

#[test]
fn redownload_release_continues_from_the_state_cursor() -> TestResult {
    // Five pages: the work floor crosses on the chain's last header, and
    // the replay overflows the regtest buffer on its fourth page — three
    // pages before the chain runs out, so the release is a buffer
    // overflow, not the completion.
    let chain = chain_on(&genesis_header(), 0, 5 * PAGE);
    let threshold = ChainWork::from(WORK_PER_HEADER * u64::try_from(5 * PAGE).unwrap_or(u64::MAX));
    assert_eq!(
        chain_work(&chain),
        threshold,
        "the floor must sit exactly on the chain's last header"
    );
    let (_genesis, sync, inbound_headers_tx, peers) = presync_fixture(threshold)?;
    let (addr, _lease, rx) = connect(&peers, 9704, 100_000);
    let source = current_source(&peers, addr);
    sync.tick();
    assert!(matches!(rx.try_recv()?, Message::GetHeaders(_)));

    for page in 0..5 {
        deliver_headers(
            &inbound_headers_tx,
            chain[page * PAGE..(page + 1) * PAGE].to_vec(),
            source,
        )?;
        sync.tick();
    }
    assert_eq!(
        sync_phase(&sync, source),
        Some(HeadersSyncPhase::Redownload),
        "the fixture must reach its second pass"
    );

    for page in 0..3 {
        deliver_headers(
            &inbound_headers_tx,
            chain[page * PAGE..(page + 1) * PAGE].to_vec(),
            source,
        )?;
        sync.tick();
    }
    while rx.try_recv().is_ok() {}
    deliver_headers(
        &inbound_headers_tx,
        chain[3 * PAGE..4 * PAGE].to_vec(),
        source,
    )?;
    sync.tick();
    assert_eq!(
        tree_node_count(&sync),
        4 * PAGE - 7_017 + 1,
        "the overflow release must retire exactly the buffer's excess"
    );
    let locator = next_locator(&rx)
        .ok_or_else(|| std::io::Error::other("the release continuation getheaders was not sent"))?;
    assert_eq!(
        locator.first().copied(),
        Some(Hash256::from(chain[4 * PAGE - 1].compute_hash()).to_le_bytes()),
        "the continuation must leave from the state's redownload cursor, not the release point",
    );

    deliver_headers(
        &inbound_headers_tx,
        chain[4 * PAGE..5 * PAGE].to_vec(),
        source,
    )?;
    sync.tick();
    assert_eq!(
        sync_phase(&sync, source),
        None,
        "a completed second pass must retire the state"
    );
    assert_eq!(
        tree_node_count(&sync),
        5 * PAGE + 1,
        "the whole replayed chain must be admitted in wire order"
    );
    Ok(())
}

#[test]
fn a_midbatch_continuity_break_spends_the_sync() -> TestResult {
    let floor =
        ChainWork::from(WORK_PER_HEADER * u64::try_from(2 * PAGE + 500).unwrap_or(u64::MAX));
    let (genesis, sync, inbound_headers_tx, peers) = presync_fixture(floor)?;
    let (addr, lease, _rx) = connect(&peers, 9705, 100_000);
    let source = current_source(&peers, addr);

    let chain = chain_on(&genesis, 0, 2 * PAGE);
    deliver_headers(&inbound_headers_tx, chain[..PAGE].to_vec(), source)?;
    sync.tick();
    assert_eq!(
        sync_phase(&sync, source),
        Some(HeadersSyncPhase::Presync),
        "the fixture must collect below the floor"
    );

    let mut midbreak = chain[PAGE..2 * PAGE - 1].to_vec();
    midbreak.push(mine_header(
        BlockHash(Hash256::from_le_bytes(&[0xa5; 32])),
        u32::try_from(2 * PAGE).unwrap_or(u32::MAX),
    ));
    deliver_headers(&inbound_headers_tx, midbreak, source)?;
    sync.tick();

    assert_eq!(
        sync_phase(&sync, source),
        None,
        "a batch that breaks continuity mid-way must spend the sync"
    );
    assert_eq!(
        tree_node_count(&sync),
        1,
        "the disconnected branch must not reach the tree"
    );
    assert!(
        !lease.is_cancelled() && peers.is_connected(addr),
        "a lost continuation is possibly benign: the connection stays"
    );
    Ok(())
}

#[test]
fn a_forwarded_body_header_leaves_the_live_sync_state_alone() -> TestResult {
    let floor = ChainWork::from(WORK_PER_HEADER * u64::try_from(4 * PAGE).unwrap_or(u64::MAX));
    let (genesis, sync, inbound_headers_tx, peers) = presync_fixture(floor)?;
    let (addr, lease, rx) = connect(&peers, 9706, 100_000);
    let source = current_source(&peers, addr);

    let chain = chain_on(&genesis, 0, PAGE);
    deliver_headers(&inbound_headers_tx, chain[..PAGE].to_vec(), source)?;
    sync.tick();
    assert_eq!(
        sync_phase(&sync, source),
        Some(HeadersSyncPhase::Presync),
        "the fixture must collect below the floor"
    );
    let cursor = with_sync_state(&sync, source, |state| state.next_locator()[0].to_le_bytes());
    while rx.try_recv().is_ok() {}

    inbound_headers_tx
        .send(InboundHeaders {
            headers: vec![mine_header(genesis.compute_hash(), 5_000)],
            source: Some(source),
            wire_response: false,
            body_fetch_owned: false,
        })
        .map_err(|err| std::io::Error::other(err.to_string()))?;
    sync.tick();

    assert_eq!(
        sync_phase(&sync, source),
        Some(HeadersSyncPhase::Presync),
        "a body-carried header must not touch the wire sync's state"
    );
    assert_eq!(
        with_sync_state(&sync, source, |state| state.next_locator()[0].to_le_bytes()),
        cursor,
        "the forwarded header must not advance the state's cursor"
    );
    assert_eq!(
        tree_node_count(&sync),
        1,
        "a header below the floor must not reach the tree through a body either"
    );
    assert!(
        rx.try_recv().is_err() && !lease.is_cancelled() && peers.is_connected(addr),
        "a forwarded header sends nothing and blames no one"
    );
    Ok(())
}

/// [`presync_fixture`] over a chain whose admission is always refused:
/// the released prefix lands on the paused-admission path.
fn presync_fixture_refusing(
    minimum_work: ChainWork,
) -> Result<PresyncFixture, Box<dyn std::error::Error>> {
    let mut tree = BlockTree::new();
    let genesis = genesis_header();
    tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
    let chain_tip = tree.tip_handle();
    let block_tree = Arc::new(RwLock::new(tree));
    let applied_tip = Arc::new(ArcSwapOption::empty());
    let peers = Arc::new(PeerTable::new());
    let (inbound_headers_tx, inbound_headers_rx) = unbounded();
    let (_inbound_blocks_tx, inbound_blocks_rx) = unbounded();
    let sync = BlockSync::new(
        Arc::new(RefusingChain(Arc::new(
            TestChain::new(chain_tip, Arc::clone(&applied_tip), Arc::clone(&block_tree))
                .with_minimum_chain_work(minimum_work),
        ))),
        Arc::clone(&peers),
        inbound_headers_rx,
        inbound_blocks_rx,
        crate::sync::syncing_ibd_latch(),
    );
    install_budget(
        &sync,
        SyncBudget {
            max_pending_blocks: 0,
            ..default_sync_budget(Network::Regtest)
        },
    );
    Ok((genesis, sync, inbound_headers_tx, peers))
}

#[test]
fn a_refused_release_drops_the_sync() -> TestResult {
    let chain = chain_on(&genesis_header(), 0, PAGE + 500);
    let threshold = chain_work(&chain);
    let (_genesis, sync, inbound_headers_tx, peers) = presync_fixture_refusing(threshold)?;
    let (addr, _lease, rx) = connect(&peers, 9706, 100_000);
    let source = current_source(&peers, addr);
    sync.tick();
    assert!(matches!(rx.try_recv()?, Message::GetHeaders(_)));

    deliver_headers(&inbound_headers_tx, chain[..PAGE].to_vec(), source)?;
    sync.tick();
    assert_eq!(sync_phase(&sync, source), Some(HeadersSyncPhase::Presync),);
    deliver_headers(&inbound_headers_tx, chain[PAGE..].to_vec(), source)?;
    sync.tick();
    assert_eq!(
        sync_phase(&sync, source),
        Some(HeadersSyncPhase::Redownload),
    );
    let _ = rx.try_iter().count();

    deliver_headers(&inbound_headers_tx, chain[..PAGE].to_vec(), source)?;
    sync.tick();
    deliver_headers(&inbound_headers_tx, chain[PAGE..].to_vec(), source)?;
    sync.tick();

    assert_eq!(
        sync_phase(&sync, source),
        None,
        "a refused release drops the sync rather than requeueing the prefix",
    );
    assert_eq!(
        tree_node_count(&sync),
        1,
        "a refused release admits nothing",
    );
    assert!(
        rx.try_iter()
            .any(|message| matches!(message, Message::GetHeaders(_))),
        "the paced ancestry retry must be on the wire",
    );
    Ok(())
}

#[test]
fn a_batch_crossing_the_floor_admits_without_presync() -> TestResult {
    let chain = chain_on(&genesis_header(), 0, 10);
    let floor = chain_work(&chain);
    let (_genesis, sync, inbound_headers_tx, peers) = presync_fixture(floor)?;
    let (addr, _lease, _rx) = connect(&peers, 9704, 100_000);
    let source = current_source(&peers, addr);

    deliver_headers(&inbound_headers_tx, chain.clone(), source)?;
    sync.tick();

    assert_eq!(
        tree_node_count(&sync),
        1 + chain.len(),
        "a batch whose claimed work reaches the floor must admit directly"
    );
    assert_eq!(
        sync_phase(&sync, source),
        None,
        "the fast path must not open a download-twice state"
    );
    Ok(())
}

#[test]
fn an_invalid_anchor_refuses_without_presync() -> TestResult {
    let floor = ChainWork::from(u64::MAX);
    let mut tree = BlockTree::new();
    let genesis = genesis_header();
    tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
    let doomed = chain_on(&genesis, 0, 3);
    let mut root = None;
    for header in &doomed {
        let id = tree.insert_header(*header, NodeStatus::HeaderValid)?;
        root = root.or(Some(id));
    }
    let root = root.ok_or_else(|| std::io::Error::other("no doomed root"))?;
    tree.invalidate_subtree(root)?;
    let doomed_len = tree.len();

    let harness = SyncHarness::with_chain_work(tree, crate::sync::syncing_ibd_latch(), floor);
    install_budget(
        &harness.sync,
        SyncBudget {
            max_pending_blocks: 0,
            ..default_sync_budget(Network::Regtest)
        },
    );
    let sync = harness.sync;
    let inbound_headers_tx = harness.inbound_headers_tx;
    let peers = harness.peers;

    let (addr, _lease, _rx) = connect(&peers, 9705, 100_000);
    let source = current_source(&peers, addr);
    let continuation = chain_on(&doomed[2], 3, 5);
    deliver_headers(&inbound_headers_tx, continuation, source)?;
    sync.tick();

    assert_eq!(
        sync_phase(&sync, source),
        None,
        "an invalid anchor must not open a download-twice state"
    );
    assert_eq!(
        tree_node_count(&sync),
        doomed_len,
        "the InvalidParent refusal must not grow the tree"
    );
    assert!(
        peers.is_connected(addr),
        "a refused anchor is not a peer fault"
    );
    Ok(())
}

#[test]
fn a_terminal_low_work_page_demotes_the_source() -> TestResult {
    let floor = ChainWork::from(u64::MAX);
    let (genesis, sync, inbound_headers_tx, peers) = presync_fixture(floor)?;
    let (addr, _lease, _rx) = connect(&peers, 9706, 100_000);
    let source = current_source(&peers, addr);
    assert_eq!(
        peers.info_of(addr).map(|info| info.best_known_height),
        Some(100_000)
    );

    let chain = chain_on(&genesis, 0, 5);
    deliver_headers(&inbound_headers_tx, chain, source)?;
    sync.tick();

    assert_eq!(
        sync_phase(&sync, source),
        None,
        "the terminal page spends the sync state"
    );
    let session = peers
        .sessions()
        .into_iter()
        .find(|session| session.addr == addr)
        .ok_or_else(|| std::io::Error::other("session vanished"))?;
    assert_eq!(
        session.headers_horizon,
        Some(5),
        "the horizon must fall to the demonstrated cursor height"
    );
    assert_eq!(
        session.info.map(|info| info.best_known_height),
        Some(100_000),
        "best_known_height must not be lowered"
    );
    assert!(
        peers.is_connected(addr),
        "a short sync below the floor is not a peer fault"
    );
    Ok(())
}

#[test]
fn unsolicited_presync_continuation_keeps_another_peers_pending_request() -> TestResult {
    let floor = ChainWork::from(WORK_PER_HEADER * u64::try_from(4 * PAGE).unwrap_or(u64::MAX));
    let (genesis, sync, inbound_headers_tx, peers) = presync_fixture(floor)?;
    let (owner_addr, _owner_lease, owner_rx) = connect(&peers, 9707, 100_000);
    sync.tick();
    let _ = next_locator(&owner_rx)
        .ok_or_else(|| std::io::Error::other("the owner request was not sent"))?;
    let owner = current_source(&peers, owner_addr);
    assert!(
        sync.scheduler
            .lock()
            .header_request
            .is_some_and(|request| request.source == owner),
        "the pending header request must belong to the first peer"
    );

    let (sender_addr, _sender_lease, sender_rx) = connect(&peers, 9708, 100_000);
    let sender = current_source(&peers, sender_addr);
    deliver_headers(&inbound_headers_tx, chain_on(&genesis, 0, PAGE), sender)?;
    sync.tick();
    assert_eq!(
        sync_phase(&sync, sender),
        Some(HeadersSyncPhase::Presync),
        "the unsolicited full page must enter presync"
    );
    let _ = next_locator(&sender_rx)
        .ok_or_else(|| std::io::Error::other("the presync continuation was not sent"))?;

    assert!(
        sync.scheduler
            .lock()
            .header_request
            .is_some_and(|request| request.source == owner),
        "an unsolicited low-work continuation must not replace another peer's request"
    );
    Ok(())
}

fn assert_invalid_body_header_is_discarded(block: Block, port: u16) -> TestResult {
    let floor = ChainWork::from(u64::MAX);
    let (_genesis, sync, _inbound_headers_tx, peers) = presync_fixture(floor)?;
    let (addr, _lease, _rx) = connect(&peers, port, 100_000);
    let source = current_source(&peers, addr);
    let hash = Hash256::from(block.block_hash());
    let mut batch = vec![crate::InboundBlock::from_decoded(block)];
    batch[0].source = Some(source);
    assert_eq!(sync.buffer_received_block_chunk(&mut batch, None), 1);
    assert!(
        sync.scheduler.lock().stager.contains(&hash),
        "the unresolved body must stage before its carried header is retried"
    );

    sync.drain_inbound_blocks();

    assert!(
        !sync.scheduler.lock().stager.contains(&hash),
        "an inadmissible carried header must release its staged body"
    );
    assert!(
        !peers.is_connected(addr),
        "a permanent header fault must disconnect the delivering peer"
    );
    assert_eq!(
        tree_node_count(&sync),
        1,
        "the invalid header must not be admitted"
    );
    Ok(())
}

#[test]
fn body_carried_low_work_bad_pow_is_discarded_and_faults_peer() -> TestResult {
    let genesis = Network::Regtest.genesis_block().header;
    let mut block = regtest_fixture::mined_block_with_prev_hash(
        genesis.compute_hash(),
        1,
        vec![regtest_fixture::coinbase(1)],
    )?;
    while bitcoin_rs_chain::compact_is_met_by(block.header.bits, Hash256::from(block.block_hash()))
    {
        block.header.nonce = block.header.nonce.wrapping_add(1);
    }

    assert_invalid_body_header_is_discarded(block, 9711)
}

#[test]
fn body_carried_low_work_bad_nbits_is_discarded_and_faults_peer() -> TestResult {
    let genesis = Network::Regtest.genesis_block().header;
    let mut block = regtest_fixture::mined_block_with_prev_hash(
        genesis.compute_hash(),
        1,
        vec![regtest_fixture::coinbase(2)],
    )?;
    block.header.bits = bitcoin_rs_primitives::CompactTarget::from_consensus(0x207f_fffe);
    while !bitcoin_rs_chain::compact_is_met_by(block.header.bits, Hash256::from(block.block_hash()))
    {
        block.header.nonce = block.header.nonce.wrapping_add(1);
    }

    assert_invalid_body_header_is_discarded(block, 9712)
}

#[test]
fn body_carried_low_work_valid_header_stays_deferred() -> TestResult {
    let floor = ChainWork::from(u64::MAX);
    let (_genesis, sync, _inbound_headers_tx, peers) = presync_fixture(floor)?;
    let (addr, _lease, _rx) = connect(&peers, 9713, 100_000);
    let source = current_source(&peers, addr);
    let genesis = Network::Regtest.genesis_block();
    let block = regtest_fixture::mined_block_with_prev_hash(
        genesis.block_hash(),
        1,
        vec![regtest_fixture::coinbase(3)],
    )?;
    let hash = Hash256::from(block.block_hash());
    let mut batch = vec![crate::InboundBlock::from_decoded(block)];
    batch[0].source = Some(source);
    assert_eq!(sync.buffer_received_block_chunk(&mut batch, None), 1);

    sync.drain_inbound_blocks();

    assert!(
        sync.scheduler.lock().stager.contains(&hash),
        "a valid below-floor body must wait for the wire presync admission"
    );
    assert!(
        peers.is_connected(addr),
        "valid carried headers do not fault the peer"
    );
    assert_eq!(
        tree_node_count(&sync),
        1,
        "the low-work header remains unadmitted"
    );
    Ok(())
}
