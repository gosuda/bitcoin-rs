//! Header-presync admission gating over the real headers drain.

use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::time::Instant;

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
    sync.scheduler
        .lock()
        .headers_sync
        .get(&source)
        .and_then(|owned| owned.presync.as_ref())
        .map(read)
}

fn sync_phase(sync: &BlockSync, source: PeerSource) -> Option<HeadersSyncPhase> {
    with_sync_state(sync, source, HeadersSyncState::phase)
}

fn pending_request(sync: &BlockSync, source: PeerSource) -> Option<super::super::HeaderRequest> {
    sync.scheduler
        .lock()
        .headers_sync
        .get(&source)
        .and_then(|owned| owned.request)
}

fn expire_request(sync: &BlockSync, source: PeerSource) -> TestResult {
    let mut scheduler = sync.scheduler.lock();
    let request = scheduler
        .headers_sync
        .get_mut(&source)
        .and_then(|owned| owned.request.as_mut())
        .ok_or("the request must still be registered")?;
    request.requested_at = Instant::now()
        .checked_sub(request.timeout())
        .ok_or_else(|| std::io::Error::other("test instant underflow"))?;
    Ok(())
}

fn assert_no_getheaders(rx: &crossbeam_channel::Receiver<Message>) {
    assert!(
        !rx.try_iter()
            .any(|message| matches!(message, Message::GetHeaders(_))),
        "no competing getheaders should reach the wire",
    );
}

fn assert_request_unchanged(
    sync: &BlockSync,
    source: PeerSource,
    expected: super::super::HeaderRequest,
) {
    assert_eq!(
        pending_request(sync, source).map(|request| {
            (
                request.locator_tip_hash,
                request.target_height,
                request.requested_at,
                request.state,
            )
        }),
        Some((
            expected.locator_tip_hash,
            expected.target_height,
            expected.requested_at,
            expected.state,
        )),
        "competing schedulers must not overwrite the owned request",
    );
}

fn assert_competing_requests_suppressed(
    sync: &BlockSync,
    source: PeerSource,
    rx: &crossbeam_channel::Receiver<Message>,
    locator: Vec<Hash256>,
    target_height: i32,
) -> TestResult {
    let expected = pending_request(sync, source).ok_or("owned request was not registered")?;
    let frontier = sync.observe_frontier(sync.observe_chain_frontier(), Instant::now());
    assert_eq!(
        sync.send_getheaders(source, 0, target_height, locator),
        super::super::GetheadersOutcome::Suppressed,
    );
    assert_eq!(
        sync.send_chain_sync_probe(&frontier, source),
        super::super::GetheadersOutcome::Suppressed,
    );
    assert!(
        !sync.probe_chain_sync(source, &frontier),
        "an owned request or live presync must not arm an eviction window",
    );
    assert_no_getheaders(rx);
    assert_request_unchanged(sync, source, expected);
    Ok(())
}

#[test]
fn empty_below_floor_reply_preserves_pacing_and_rotates_without_retirement() -> TestResult {
    let floor = ChainWork::from(WORK_PER_HEADER * u64::try_from(4 * PAGE).unwrap_or(u64::MAX));
    let (genesis, sync, inbound_headers_tx, peers) = presync_fixture(floor)?;
    sync.chain.bootstrap_genesis();
    let fork = chain_on(&genesis, 0, 1);
    assert!(matches!(
        sync.chain.admit_headers(&fork),
        super::super::chain::HeaderAdmission::Accepted { .. }
    ));
    let (first_addr, _first_lease, first_rx) = connect(&peers, 9710, 100_000);
    let (second_addr, _second_lease, second_rx) = connect(&peers, 9711, 100_000);
    let first = current_source(&peers, first_addr);
    let second = current_source(&peers, second_addr);

    sync.tick();
    assert!(matches!(first_rx.try_recv()?, Message::GetHeaders(_)));
    assert!(second_rx.try_recv().is_err());
    let initial = pending_request(&sync, first).ok_or("the first request was not registered")?;
    assert_eq!(
        initial.state,
        super::super::HeaderRequestState::AwaitingResponse
    );

    inbound_headers_tx.send(InboundHeaders {
        headers: Vec::new(),
        source: Some(first),
        wire_response: true,
        body_fetch_owned: false,
    })?;
    sync.tick();
    let answered = pending_request(&sync, first).ok_or("the empty reply lost its request")?;
    assert_eq!(answered.state, super::super::HeaderRequestState::Answered);
    assert_eq!(answered.requested_at, initial.requested_at);
    assert_eq!(answered.locator_tip_hash, initial.locator_tip_hash);
    assert_eq!(answered.target_height, initial.target_height);
    assert_no_getheaders(&first_rx);
    assert_no_getheaders(&second_rx);

    let frontier = sync.observe_frontier(sync.observe_chain_frontier(), Instant::now());
    assert_eq!(
        sync.send_getheaders(first, 0, 1, vec![Hash256::from(genesis.compute_hash())],),
        super::super::GetheadersOutcome::Suppressed,
    );
    assert!(
        !sync.probe_chain_sync(first, &frontier),
        "an answered pacing gate must not arm an eviction window",
    );
    assert_request_unchanged(&sync, first, answered);
    assert_no_getheaders(&first_rx);

    expire_request(&sync, first)?;
    sync.tick();
    assert!(
        peers.is_current(first),
        "an answered request cannot retire its peer"
    );
    assert_eq!(
        pending_request(&sync, first).map(|request| request.state),
        Some(super::super::HeaderRequestState::Answered),
    );
    assert!(first_rx.try_recv().is_err());
    assert!(matches!(second_rx.try_recv()?, Message::GetHeaders(_)));
    assert_eq!(sync.scheduler.lock().header_request_owner, Some(second));

    let chain = chain_on(&genesis, 0, PAGE);
    deliver_headers(&inbound_headers_tx, chain, second)?;
    sync.tick();
    let _ = next_locator(&second_rx).ok_or("the second peer's presync request was not sent")?;
    let before_empty =
        pending_request(&sync, second).ok_or("the second request was not tracked")?;
    assert_eq!(sync_phase(&sync, second), Some(HeadersSyncPhase::Presync));
    assert!(
        sync.scheduler
            .lock()
            .headers_sync
            .get(&second)
            .is_some_and(|owned| owned.presync.is_some()),
        "a live presync cursor shares the request's lifecycle entry",
    );

    inbound_headers_tx.send(InboundHeaders {
        headers: Vec::new(),
        source: Some(second),
        wire_response: true,
        body_fetch_owned: false,
    })?;
    sync.drain_inbound_headers();
    let answered = pending_request(&sync, second).ok_or("the empty answer lost its pacing gate")?;
    assert_eq!(answered.state, super::super::HeaderRequestState::Answered);
    assert_eq!(answered.requested_at, before_empty.requested_at);
    assert_eq!(sync_phase(&sync, second), None);
    assert!(
        sync.scheduler
            .lock()
            .headers_sync
            .get(&second)
            .is_some_and(|owned| owned.request.is_some() && owned.presync.is_none()),
        "an empty answer clears only the nested presync state",
    );
    Ok(())
}

#[test]
fn unowned_below_floor_peer_receives_one_tracked_chain_sync_probe() -> TestResult {
    let floor = ChainWork::from(WORK_PER_HEADER * u64::try_from(4 * PAGE).unwrap_or(u64::MAX));
    let (genesis, sync, inbound_headers_tx, peers) = presync_fixture(floor)?;
    sync.chain.bootstrap_genesis();
    let (addr, _lease, rx) = connect(&peers, 9712, 100_000);
    let source = current_source(&peers, addr);
    let frontier = sync.observe_frontier(sync.observe_chain_frontier(), Instant::now());

    assert!(
        sync.probe_chain_sync(source, &frontier),
        "an unowned source must receive its real below-floor probe",
    );
    assert!(matches!(rx.try_recv()?, Message::GetHeaders(_)));
    let request = pending_request(&sync, source).ok_or("the probe was not tracked")?;
    assert_eq!(
        request.state,
        super::super::HeaderRequestState::AwaitingResponse
    );
    assert_eq!(
        sync.send_getheaders(source, 0, 100, vec![Hash256::from(genesis.compute_hash())],),
        super::super::GetheadersOutcome::Suppressed,
        "an unanswered below-floor request owns this exact connection",
    );
    assert!(
        !sync.probe_chain_sync(source, &frontier),
        "a second probe must not borrow the first request's response window",
    );
    assert_no_getheaders(&rx);

    inbound_headers_tx.send(InboundHeaders {
        headers: chain_on(&genesis, 0, PAGE),
        source: Some(source),
        wire_response: true,
        body_fetch_owned: false,
    })?;
    sync.tick();
    assert_eq!(
        sync_phase(&sync, source),
        Some(HeadersSyncPhase::Presync),
        "the real response must establish the download-twice owner",
    );
    assert!(
        sync.scheduler
            .lock()
            .headers_sync
            .get(&source)
            .is_some_and(|owned| owned.request.is_some() && owned.presync.is_some()),
        "the presync continuation and request share one lifecycle entry",
    );
    let _ = rx.try_iter().collect::<Vec<_>>();
    let frontier = sync.observe_frontier(sync.observe_chain_frontier(), Instant::now());
    assert!(
        !sync.probe_chain_sync(source, &frontier),
        "a live PRESYNC cursor must not arm a chain-sync eviction window",
    );
    assert_no_getheaders(&rx);
    Ok(())
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
fn owned_header_requests_suppress_competing_frontier_and_chain_sync_requests() -> TestResult {
    let chain = chain_on(&genesis_header(), 0, PAGE + 500);
    let threshold = chain_work(&chain);
    let (_genesis, sync, inbound_headers_tx, peers) = presync_fixture(threshold)?;
    let (addr, _lease, rx) = connect(&peers, 9720, 100_000);
    let source = current_source(&peers, addr);
    let competing_locator = vec![Hash256::from(chain[0].compute_hash())];

    sync.tick();
    let _ = next_locator(&rx).ok_or("the initial getheaders was not sent")?;
    assert_competing_requests_suppressed(&sync, source, &rx, competing_locator.clone(), 7)?;

    deliver_headers(&inbound_headers_tx, chain[..PAGE].to_vec(), source)?;
    sync.tick();
    let _ = next_locator(&rx).ok_or("the presync continuation was not sent")?;
    assert_eq!(
        sync_phase(&sync, source),
        Some(HeadersSyncPhase::Presync),
        "the first page must enter presync",
    );
    assert_competing_requests_suppressed(&sync, source, &rx, competing_locator.clone(), 8)?;

    deliver_headers(&inbound_headers_tx, chain[PAGE..].to_vec(), source)?;
    sync.tick();
    let _ = next_locator(&rx).ok_or("the redownload request was not sent")?;
    assert_eq!(
        sync_phase(&sync, source),
        Some(HeadersSyncPhase::Redownload),
        "the crossing page must enter redownload",
    );
    assert!(
        sync.scheduler
            .lock()
            .headers_sync
            .get(&source)
            .is_some_and(|owned| owned.request.is_some() && owned.presync.is_some()),
        "the redownload request and validation cursor share one lifecycle entry",
    );
    assert_competing_requests_suppressed(&sync, source, &rx, competing_locator, 9)?;
    Ok(())
}

#[test]
#[expect(clippy::too_many_lines)]
fn expired_header_syncs_drop_delayed_pages_before_recovery() -> TestResult {
    let chain = chain_on(&genesis_header(), 0, PAGE + 500);
    let threshold = chain_work(&chain);
    let (_genesis, sync, inbound_headers_tx, peers) = presync_fixture(threshold)?;
    let (addr_a, _lease_a, rx_a) = connect(&peers, 9721, 100_000);
    let source_a = current_source(&peers, addr_a);
    let (addr_b, _lease_b, rx_b) = connect(&peers, 9722, 100_000);
    let source_b = current_source(&peers, addr_b);

    // The first request can expire before it has created a PRESYNC state.
    sync.tick();
    let _ = next_locator(&rx_a).ok_or("the initial request was not sent")?;
    deliver_headers(&inbound_headers_tx, chain[..PAGE].to_vec(), source_a)?;
    expire_request(&sync, source_a)?;
    sync.tick();
    let _ = next_locator(&rx_b).ok_or("the first recovery request was not sent")?;
    assert!(
        !peers.is_connected(addr_a),
        "the timed-out source must disconnect"
    );
    assert_eq!(sync_phase(&sync, source_a), None);
    assert!(pending_request(&sync, source_a).is_none());
    assert!(!sync.scheduler.lock().headers_sync.contains_key(&source_a));
    assert_eq!(
        tree_node_count(&sync),
        1,
        "a delayed response after initial timeout must not be admitted",
    );

    // Expire a live PRESYNC continuation while its next page is queued.
    deliver_headers(&inbound_headers_tx, chain[..PAGE].to_vec(), source_b)?;
    sync.tick();
    let _ = next_locator(&rx_b).ok_or("the presync continuation was not sent")?;
    assert_eq!(sync_phase(&sync, source_b), Some(HeadersSyncPhase::Presync));
    let (addr_c, _lease_c, rx_c) = connect(&peers, 9723, 100_000);
    let source_c = current_source(&peers, addr_c);
    deliver_headers(&inbound_headers_tx, chain[PAGE..].to_vec(), source_b)?;
    expire_request(&sync, source_b)?;
    sync.tick();
    let _ = next_locator(&rx_c).ok_or("the presync recovery request was not sent")?;
    assert!(
        !peers.is_connected(addr_b),
        "the presync timeout must disconnect its source"
    );
    assert_eq!(sync_phase(&sync, source_b), None);
    assert!(pending_request(&sync, source_b).is_none());
    assert!(!sync.scheduler.lock().headers_sync.contains_key(&source_b));
    assert_eq!(
        tree_node_count(&sync),
        1,
        "a delayed presync page must not be admitted after timeout",
    );

    // Bring the recovery source through PRESYNC and into REDOWNLOAD, then
    // expire that cursor with a replay page already waiting in the queue.
    deliver_headers(&inbound_headers_tx, chain[..PAGE].to_vec(), source_c)?;
    sync.tick();
    let _ = next_locator(&rx_c).ok_or("the recovery presync continuation was not sent")?;
    deliver_headers(&inbound_headers_tx, chain[PAGE..].to_vec(), source_c)?;
    sync.tick();
    let _ = next_locator(&rx_c).ok_or("the recovery redownload request was not sent")?;
    assert_eq!(
        sync_phase(&sync, source_c),
        Some(HeadersSyncPhase::Redownload)
    );
    assert!(
        sync.scheduler
            .lock()
            .headers_sync
            .get(&source_c)
            .is_some_and(|owned| owned.request.is_some() && owned.presync.is_some()),
    );
    let (addr_d, _lease_d, rx_d) = connect(&peers, 9724, 100_000);
    let source_d = current_source(&peers, addr_d);
    deliver_headers(&inbound_headers_tx, chain[..PAGE].to_vec(), source_c)?;
    expire_request(&sync, source_c)?;
    sync.tick();
    let _ = next_locator(&rx_d).ok_or("the redownload recovery request was not sent")?;
    assert!(
        !peers.is_connected(addr_c),
        "the redownload timeout must disconnect its source"
    );
    assert_eq!(sync_phase(&sync, source_c), None);
    assert!(pending_request(&sync, source_c).is_none());
    assert!(!sync.scheduler.lock().headers_sync.contains_key(&source_c));
    assert_eq!(
        tree_node_count(&sync),
        1,
        "the work floor must still block admission before replay",
    );

    // The replacement follows the established two-pass path and only the
    // redownload pass may admit the chain.
    deliver_headers(&inbound_headers_tx, chain[..PAGE].to_vec(), source_d)?;
    sync.tick();
    let _ = next_locator(&rx_d).ok_or("the final presync continuation was not sent")?;
    assert_eq!(sync_phase(&sync, source_d), Some(HeadersSyncPhase::Presync));
    deliver_headers(&inbound_headers_tx, chain[PAGE..].to_vec(), source_d)?;
    sync.tick();
    let _ = next_locator(&rx_d).ok_or("the final redownload request was not sent")?;
    assert_eq!(
        sync_phase(&sync, source_d),
        Some(HeadersSyncPhase::Redownload)
    );
    assert_eq!(tree_node_count(&sync), 1);
    deliver_headers(&inbound_headers_tx, chain[..PAGE].to_vec(), source_d)?;
    sync.tick();
    let _ = next_locator(&rx_d).ok_or("the replay continuation was not sent")?;
    deliver_headers(&inbound_headers_tx, chain[PAGE..].to_vec(), source_d)?;
    sync.tick();
    assert_eq!(
        sync.chain.block_tree().height_of_hash(Hash256::from(
            chain.last().ok_or("empty chain")?.compute_hash()
        )),
        Some(u32::try_from(chain.len()).unwrap_or(u32::MAX)),
        "recovery must admit the replayed chain",
    );
    assert_eq!(sync_phase(&sync, source_d), None);
    Ok(())
}

#[test]
fn replaced_connection_cannot_admit_queued_predecessor_headers() -> TestResult {
    let chain = chain_on(&genesis_header(), 0, PAGE + 500);
    let threshold = chain_work(&chain);
    let (_genesis, sync, inbound_headers_tx, peers) = presync_fixture(threshold)?;
    let (addr, old_lease, old_rx) = connect(&peers, 9725, 100_000);
    let old_source = current_source(&peers, addr);
    sync.tick();
    let _ = next_locator(&old_rx).ok_or("the predecessor request was not sent")?;
    deliver_headers(&inbound_headers_tx, chain[..PAGE].to_vec(), old_source)?;
    sync.tick();
    let _ = next_locator(&old_rx).ok_or("the predecessor presync request was not sent")?;
    assert_eq!(
        sync_phase(&sync, old_source),
        Some(HeadersSyncPhase::Presync)
    );
    assert!(
        sync.scheduler
            .lock()
            .headers_sync
            .get(&old_source)
            .is_some_and(|owned| owned.request.is_some() && owned.presync.is_some()),
        "the predecessor has both lifecycle facts before replacement",
    );

    let (replacement_tx, replacement_rx) = unbounded::<Message>();
    let replacement_lease = PeerLease::new(replacement_tx);
    peers.register(addr, replacement_lease.clone());
    peers.publish_info(addr, &replacement_lease, synthetic_peer(addr, 100_000));
    let replacement = current_source(&peers, addr);

    sync.tick();
    let _ = next_locator(&replacement_rx).ok_or("the replacement request was not sent")?;
    assert!(old_lease.is_cancelled());
    assert_eq!(sync_phase(&sync, old_source), None);
    assert!(pending_request(&sync, old_source).is_none());
    assert!(!sync.scheduler.lock().headers_sync.contains_key(&old_source));
    assert_eq!(
        pending_request(&sync, replacement).map(|request| request.source),
        Some(replacement),
        "replacement ownership must be published under its exact identity",
    );

    deliver_headers(&inbound_headers_tx, chain[..PAGE].to_vec(), replacement)?;
    sync.tick();
    let _ =
        next_locator(&replacement_rx).ok_or("the replacement presync continuation was not sent")?;
    assert_eq!(
        sync_phase(&sync, replacement),
        Some(HeadersSyncPhase::Presync),
        "the replacement must retain its own presync state",
    );
    assert!(
        sync.scheduler
            .lock()
            .headers_sync
            .get(&replacement)
            .is_some_and(|owned| owned.request.is_some() && owned.presync.is_some()),
        "the replacement owns its request and presync together",
    );
    let replacement_request =
        pending_request(&sync, replacement).ok_or("replacement request was not registered")?;

    // This whole batch would cross the work floor and admit directly if the
    // predecessor were still current. It must leave the live replacement alone.
    deliver_headers(&inbound_headers_tx, chain, old_source)?;
    sync.tick();
    assert_no_getheaders(&replacement_rx);
    assert_eq!(
        sync_phase(&sync, replacement),
        Some(HeadersSyncPhase::Presync),
        "a stale batch must leave the replacement's sync state intact",
    );
    assert_eq!(
        pending_request(&sync, replacement).map(|request| request.source),
        Some(replacement),
        "a stale predecessor delivery must not overwrite replacement request ownership",
    );
    assert_request_unchanged(&sync, replacement, replacement_request);
    assert_eq!(
        tree_node_count(&sync),
        1,
        "a queued directly-admissible predecessor batch must not enter the tree",
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
            .header_request()
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
            .header_request()
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
