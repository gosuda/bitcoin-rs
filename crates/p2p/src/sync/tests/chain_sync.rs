//! Chain-sync eviction: the twenty-minute timeout, the one probe that ends
//! it, the two-minute response window, and the protection that spares the
//! first four outbound connections to reach the tip.

use std::time::Duration;

use super::*;
use crate::download_window::MINIMUM_CONNECT_TIME;
use crate::peer_info::PeerRole;
use crate::sync::GetheadersOutcome;
use crate::sync::frontier::UsablePeer;
use crate::sync::peers::{
    ChainSyncAction, ChainSyncState, HEADERS_RESPONSE_TIME, chain_sync_subject, consider_eviction,
};

/// An outbound connection that demonstrated `height`.
fn outbound(port: u16, height: u32, role: PeerRole, at: Instant) -> UsablePeer {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    UsablePeer {
        source: PeerSource::for_test(addr),
        info: synthetic_peer(addr, i32::try_from(height).unwrap_or(i32::MAX)),
        demonstrated_tips: vec![Hash256::from_le_bytes(&[0x7c; 32])],
        active_height: Some(height),
        headers_horizon: None,
        role,
        manual: false,
        connected_at: at,
    }
}

/// An inbound connection at `height`: we did not choose it, so the timer must
/// not judge it.
fn inbound(port: u16, height: u32, at: Instant) -> UsablePeer {
    let mut peer = outbound(port, height, PeerRole::FullRelay, at);
    peer.info.inbound = true;
    peer
}

/// An outbound connection that only CLAIMED `height` in its handshake and
/// has handed us no headers: Core's `pindexBestKnownBlock` is still null.
fn claiming(port: u16, height: u32, at: Instant) -> UsablePeer {
    let mut peer = outbound(port, height, PeerRole::FullRelay, at);
    peer.demonstrated_tips.clear();
    peer
}

/// An outbound connection to an address the operator named, which Core marks
/// `MANUAL` (`net_processing.cpp:5502`).
fn pinned(port: u16, height: u32, at: Instant) -> UsablePeer {
    let mut peer = outbound(port, height, PeerRole::FullRelay, at);
    peer.manual = true;
    peer
}

#[test]
fn a_claimed_height_without_headers_is_probed_then_retired() {
    let t0 = Instant::now();
    let peer = claiming(9_603, 100, t0);
    let mut state = ChainSyncState::default();
    let mut protected = 0;

    assert_eq!(
        consider_eviction(&peer, &mut state, 100, t0, &mut protected),
        None,
        "the first tick arms the silent claimant"
    );
    assert!(
        !state.is_protected(),
        "a height the peer only claimed earns no protection"
    );
    assert_eq!(protected, 0, "the protection pool is untouched");
    assert_eq!(
        consider_eviction(
            &peer,
            &mut state,
            100,
            t0 + Duration::from_mins(20),
            &mut protected
        ),
        Some(ChainSyncAction::Probe),
        "the claimant answers to the timeout"
    );
    assert_eq!(
        consider_eviction(
            &peer,
            &mut state,
            100,
            t0 + Duration::from_mins(22),
            &mut protected
        ),
        Some(ChainSyncAction::Evict),
        "and it is retired when the probe goes unanswered"
    );
}

#[test]
fn behind_tip_connection_is_probed_then_retired() {
    let t0 = Instant::now();
    let peer = outbound(9_601, 99, PeerRole::FullRelay, t0);
    let mut state = ChainSyncState::default();
    let mut protected = 0;

    assert_eq!(
        consider_eviction(&peer, &mut state, 100, t0, &mut protected),
        None,
        "the first sight of a lagging connection only arms it"
    );
    assert_eq!(
        consider_eviction(
            &peer,
            &mut state,
            100,
            t0 + Duration::from_mins(19),
            &mut protected
        ),
        None,
        "nineteen minutes of silence is still inside the timeout"
    );
    assert_eq!(
        consider_eviction(
            &peer,
            &mut state,
            100,
            t0 + Duration::from_mins(20),
            &mut protected
        ),
        Some(ChainSyncAction::Probe),
        "at the timeout the connection gets exactly one probe"
    );
    assert_eq!(
        consider_eviction(
            &peer,
            &mut state,
            100,
            t0 + Duration::from_mins(21),
            &mut protected
        ),
        None,
        "the response window is still open"
    );
    assert_eq!(
        consider_eviction(
            &peer,
            &mut state,
            100,
            t0 + Duration::from_mins(22),
            &mut protected
        ),
        Some(ChainSyncAction::Evict),
        "a window later, with nothing to show, it is retired"
    );
    assert_eq!(protected, 0, "a lagging connection earns no protection");
}

#[test]
fn tip_reaching_connection_is_protected_from_the_timer() {
    let t0 = Instant::now();
    let at_tip = outbound(9_602, 100, PeerRole::FullRelay, t0);
    let mut state = ChainSyncState::default();
    let mut protected = 0;

    assert_eq!(
        consider_eviction(&at_tip, &mut state, 100, t0, &mut protected),
        None
    );
    assert_eq!(protected, 1, "the connection took a protection slot");

    for minutes in [30, 60, 120] {
        assert_eq!(
            consider_eviction(
                &at_tip,
                &mut state,
                500,
                t0 + Duration::from_secs(minutes * 60),
                &mut protected
            ),
            None,
            "a protected connection is never probed or retired at {minutes} minutes"
        );
    }
    assert_eq!(protected, 1, "protection is not counted twice");
}

#[test]
fn protection_is_bounded_to_four_connections() {
    let t0 = Instant::now();
    let mut protected = 0;
    let mut states = Vec::new();
    for idx in 0..4_u16 {
        let peer = outbound(9_610 + idx, 100, PeerRole::FullRelay, t0);
        let mut state = ChainSyncState::default();
        assert_eq!(
            consider_eviction(&peer, &mut state, 100, t0, &mut protected),
            None
        );
        states.push(state);
    }
    assert_eq!(protected, 4, "the protection pool is full");
    assert!(
        states.iter().all(ChainSyncState::is_protected),
        "each of the four holds protection"
    );

    let fifth = outbound(9_614, 99, PeerRole::FullRelay, t0);
    let mut state = ChainSyncState::default();
    assert_eq!(
        consider_eviction(&fifth, &mut state, 100, t0, &mut protected),
        None,
        "the fifth connection is armed, not protected"
    );
    assert_eq!(
        consider_eviction(
            &fifth,
            &mut state,
            100,
            t0 + Duration::from_mins(20),
            &mut protected
        ),
        Some(ChainSyncAction::Probe),
        "and it answers to the timer"
    );
}

#[test]
fn only_aged_outbound_full_relay_connections_are_subjects() {
    let t0 = Instant::now();
    let aged = t0 + MINIMUM_CONNECT_TIME;
    assert!(chain_sync_subject(
        &outbound(9_620, 1, PeerRole::FullRelay, t0),
        aged
    ));
    assert!(
        !chain_sync_subject(
            &outbound(9_621, 1, PeerRole::FullRelay, t0),
            t0 + Duration::from_secs(29)
        ),
        "a connection younger than the minimum is not judged"
    );
    assert!(
        !chain_sync_subject(&outbound(9_622, 1, PeerRole::BlockRelayOnly, t0), aged),
        "a block-relay-only connection is never asked to bring a chain"
    );
    assert!(
        !chain_sync_subject(&inbound(9_623, 1, t0), aged),
        "an inbound connection is never timed out"
    );
    assert!(
        !chain_sync_subject(&pinned(9_624, 1, t0), aged),
        "the operator asked for this one by name, so the timer never judges it"
    );
}

#[test]
fn progress_to_the_benchmark_re_arms_the_timeout() {
    let t0 = Instant::now();
    let mut state = ChainSyncState::default();
    let mut protected = 0;
    let lagging = outbound(9_604, 99, PeerRole::FullRelay, t0);
    assert_eq!(
        consider_eviction(&lagging, &mut state, 100, t0, &mut protected),
        None,
        "the first sight of the lag arms it with the tip-100 benchmark"
    );

    let at_benchmark = outbound(9_604, 100, PeerRole::FullRelay, t0);
    assert_eq!(
        consider_eviction(
            &at_benchmark,
            &mut state,
            150,
            t0 + Duration::from_mins(19),
            &mut protected
        ),
        None,
        "reaching the benchmark is progress, not a conviction"
    );
    assert_eq!(
        consider_eviction(
            &at_benchmark,
            &mut state,
            150,
            t0 + Duration::from_mins(20),
            &mut protected
        ),
        None,
        "the re-armed window runs twenty minutes from the progress, not the first arm"
    );
    assert_eq!(
        consider_eviction(
            &at_benchmark,
            &mut state,
            150,
            t0 + Duration::from_mins(39),
            &mut protected
        ),
        Some(ChainSyncAction::Probe),
        "twenty minutes after the re-arm it owes the probe"
    );
    assert_eq!(
        consider_eviction(
            &at_benchmark,
            &mut state,
            150,
            t0 + Duration::from_mins(41),
            &mut protected
        ),
        Some(ChainSyncAction::Evict),
        "and the response window still closes on it"
    );
}

#[test]
#[expect(clippy::expect_used)]
fn an_unsent_chain_sync_probe_arms_no_response_window() {
    let t0 = Instant::now();
    let (mut tree, blocks) = mined_chain(1, 1).expect("fixture chain mines");
    let chain_tip = tree.tip_handle();
    let sync = Arc::new(BlockSync::new(
        Arc::new(TestChain::new(
            chain_tip,
            Arc::new(ArcSwapOption::empty()),
            Arc::new(RwLock::new(tree)),
        )),
        Arc::new(PeerTable::new()),
        {
            let (_tx, rx) = unbounded::<crate::InboundHeaders>();
            rx
        },
        {
            let (_tx, rx) = unbounded::<crate::InboundBlock>();
            rx
        },
        super::synced_ibd_latch(),
    ));
    sync.chain.bootstrap_genesis();
    stage_body(&sync, &blocks[0]);

    let chain_frontier = sync.observe_chain_frontier();
    let frontier = sync.observe_frontier(chain_frontier, t0);
    let subject = outbound(9_630, 0, PeerRole::FullRelay, t0);

    assert!(
        frontier.chain.next_required.is_some(),
        "premise: the fixture owes a body, so the frontier can be owned"
    );
    assert!(
        !sync.probe_chain_sync(subject.source, &frontier),
        "a probe that never reached the wire is not a probe"
    );
    assert!(
        !sync
            .scheduler
            .lock()
            .chain_sync
            .contains_key(&subject.source),
        "no response window is armed for a probe the connection never received"
    );
}

#[test]
#[expect(clippy::expect_used)]
fn chain_sync_probe_locator_anchors_at_the_header_tips_parent() {
    let t0 = Instant::now();
    let (tree, _blocks) = mined_chain(1, 2).expect("fixture chain mines");
    let SyncHarness {
        sync,
        peers,
        block_tree,
        ..
    } = SyncHarness::new(tree);
    sync.chain.bootstrap_genesis();
    let chain_frontier = sync.observe_chain_frontier();
    let frontier = sync.observe_frontier(chain_frontier, t0);
    let tip = frontier
        .chain
        .chain_tip
        .as_ref()
        .expect("the fixture mines a header tip")
        .clone();
    assert_eq!(tip.height, 3, "premise: header tip is height 3");

    let addr = test_addr(9_900, 0).expect("test address builds");
    let rx = connect_peer(&peers, synthetic_peer(addr, i32::MAX));
    let outcome = sync.send_chain_sync_probe(&frontier, current_source(&peers, addr));
    assert_eq!(outcome, GetheadersOutcome::Sent);

    let Ok(Message::GetHeaders(getheaders)) = rx.try_recv() else {
        panic!("the probe enqueues one getheaders");
    };
    let parent = block_tree
        .read()
        .node(tip.tip_id)
        .expect("tip is in the tree")
        .parent
        .expect("a height-3 tip has a parent");
    let expected = block_tree
        .read()
        .node(parent)
        .expect("parent is in the tree")
        .hash;
    assert_eq!(
        getheaders.locator_hashes.first(),
        Some(&bitcoin::BlockHash::from_byte_array(
            *expected.as_byte_array()
        )),
        "the locator roots at the header tip's parent so the answer carries the tip"
    );
}

#[test]
fn frontier_and_eviction_probes_do_not_overwrite_live_requests() -> TestResult {
    let (tree, blocks) = mined_chain(1, 2)?;
    let harness = SyncHarness::new(tree);
    let sync = harness.sync;
    let peers = harness.peers;
    let inbound_headers_tx = harness.inbound_headers_tx;
    sync.chain.bootstrap_genesis();

    let addr = test_addr(9_940, 0)?;
    let rx = connect_peer(&peers, synthetic_peer(addr, i32::MAX));
    let source = current_source(&peers, addr);
    let frontier = sync.observe_frontier(sync.observe_chain_frontier(), Instant::now());
    let request_snapshot = || {
        let scheduler = sync.scheduler.lock();
        let request = scheduler.headers_sync.get(&source)?.request?;
        Some((
            request.locator_tip_hash,
            request.target_height,
            request.requested_at,
            request.state,
            request.kind,
        ))
    };
    let header_tip = frontier
        .chain
        .chain_tip
        .as_ref()
        .ok_or("the fixture must have a header tip")?;
    let chain_probe_locator = {
        let tree = sync.chain.block_tree();
        let parent = tree
            .node(header_tip.tip_id)
            .ok()
            .and_then(|node| node.parent)
            .ok_or("the header tip must have a parent")?;
        tree.node(parent)
            .ok()
            .map(|node| node.hash)
            .ok_or("the parent must be in the tree")?
    };

    assert_eq!(
        sync.probe_frontier_peer(&frontier, source),
        GetheadersOutcome::Sent,
    );
    assert!(matches!(rx.try_recv()?, Message::GetHeaders(_)));
    let frontier_request = request_snapshot().ok_or("the frontier request was not registered")?;
    assert_ne!(
        frontier_request.0, chain_probe_locator,
        "the two probe classes ask from different locators",
    );
    assert_eq!(
        (frontier_request.3, frontier_request.4),
        (
            super::super::HeaderRequestState::AwaitingResponse,
            super::super::HeaderRequestKind::Frontier,
        ),
    );
    assert!(
        !sync.probe_chain_sync(source, &frontier),
        "an eviction probe cannot borrow a frontier request's response",
    );
    assert!(rx.try_recv().is_err());
    assert_eq!(request_snapshot(), Some(frontier_request));

    inbound_headers_tx.send(crate::InboundHeaders {
        headers: vec![blocks[0].header],
        source: Some(source),
        wire_response: true,
        body_fetch_owned: false,
    })?;
    sync.drain_inbound_headers();
    let _ = rx.try_iter().collect::<Vec<_>>();
    assert!(
        !sync.scheduler.lock().headers_sync.contains_key(&source),
        "the real wire answer must consume the frontier request",
    );

    assert!(
        sync.probe_chain_sync(source, &frontier),
        "an unowned source can receive its eviction probe",
    );
    assert!(matches!(rx.try_recv()?, Message::GetHeaders(_)));
    let eviction_request = request_snapshot().ok_or("the eviction probe was not registered")?;
    assert_eq!(eviction_request.0, chain_probe_locator);
    assert_eq!(
        (eviction_request.3, eviction_request.4),
        (
            super::super::HeaderRequestState::AwaitingResponse,
            super::super::HeaderRequestKind::ChainSyncProbe,
        ),
    );
    assert_eq!(
        sync.send_getheaders(
            source,
            0,
            i32::try_from(frontier_request.1).unwrap_or(i32::MAX),
            vec![frontier_request.0],
        ),
        GetheadersOutcome::Suppressed,
        "a frontier request cannot overwrite the live eviction probe",
    );
    assert!(rx.try_recv().is_err());
    assert_eq!(request_snapshot(), Some(eviction_request));
    Ok(())
}

#[test]
fn chain_sync_probe_holds_request_for_its_response_window() -> TestResult {
    let (tree, blocks) = mined_chain(1, 2)?;
    let harness = SyncHarness::new(tree);
    let sync = harness.sync;
    let peers = harness.peers;
    let inbound_headers_tx = harness.inbound_headers_tx;
    sync.chain.bootstrap_genesis();

    let addr = test_addr(9_942, 0)?;
    let rx = connect_peer(&peers, synthetic_peer(addr, i32::MAX));
    let source = current_source(&peers, addr);
    let frontier = sync.observe_frontier(sync.observe_chain_frontier(), Instant::now());
    assert!(sync.probe_chain_sync(source, &frontier));
    assert!(matches!(rx.try_recv()?, Message::GetHeaders(_)));

    let request_snapshot = || {
        let scheduler = sync.scheduler.lock();
        let request = scheduler.headers_sync.get(&source)?.request?;
        Some((
            request.locator_tip_hash,
            request.target_height,
            request.requested_at,
            request.state,
            request.kind,
        ))
    };
    let probe_request = request_snapshot().ok_or("the probe request was not registered")?;
    assert_eq!(
        probe_request.4,
        super::super::HeaderRequestKind::ChainSyncProbe,
    );
    let competing_locator = Hash256::default();
    let competing_target = i32::MAX;
    assert_ne!(probe_request.0, competing_locator);
    assert_ne!(
        probe_request.1,
        u32::try_from(competing_target).unwrap_or(0),
    );
    let request_age = HEADERS_RESPONSE_TIME
        .checked_sub(Duration::from_secs(10))
        .ok_or("the probe response window must exceed its margin")?;
    assert!(request_age > super::super::HEADER_REQUEST_TIMEOUT);
    {
        let mut scheduler = sync.scheduler.lock();
        let request = scheduler
            .headers_sync
            .get_mut(&source)
            .and_then(|owned| owned.request.as_mut())
            .ok_or("the probe request must still be registered")?;
        request.requested_at = Instant::now()
            .checked_sub(request_age)
            .ok_or("the test instant must allow the probe age")?;
    }
    let aged_request = request_snapshot().ok_or("the aged probe must remain registered")?;
    assert_eq!(
        sync.send_getheaders(source, 0, competing_target, vec![competing_locator],),
        GetheadersOutcome::Suppressed,
        "an unanswered chain-sync probe owns its connection for two minutes",
    );
    assert!(rx.try_recv().is_err());
    assert_eq!(request_snapshot(), Some(aged_request));

    inbound_headers_tx.send(crate::InboundHeaders {
        headers: vec![blocks[0].header],
        source: Some(source),
        wire_response: true,
        body_fetch_owned: false,
    })?;
    sync.drain_inbound_headers();
    let _ = rx.try_iter().collect::<Vec<_>>();
    assert!(
        !sync.scheduler.lock().headers_sync.contains_key(&source),
        "the nonempty wire answer must release the probe request",
    );
    assert_eq!(
        sync.send_getheaders(source, 0, competing_target, vec![competing_locator],),
        GetheadersOutcome::Sent,
        "a real answer frees the connection for frontier work",
    );
    assert!(matches!(rx.try_recv()?, Message::GetHeaders(_)));
    assert_eq!(
        sync.scheduler
            .lock()
            .headers_sync
            .get(&source)
            .and_then(|owned| owned.request)
            .map(|request| request.kind),
        Some(super::super::HeaderRequestKind::Frontier),
    );
    Ok(())
}

#[test]
fn replacing_expired_frontier_with_chain_sync_probe_releases_owner() -> TestResult {
    let (tree, _blocks) = mined_chain(1, 2)?;
    let harness = SyncHarness::new(tree);
    let sync = harness.sync;
    let peers = harness.peers;
    sync.chain.bootstrap_genesis();

    let frontier_addr = test_addr(9_943, 0)?;
    let other_addr = test_addr(9_944, 0)?;
    let frontier_rx = connect_peer(&peers, synthetic_peer(frontier_addr, i32::MAX));
    let other_rx = connect_peer(&peers, synthetic_peer(other_addr, i32::MAX));
    let frontier_source = current_source(&peers, frontier_addr);
    let other_source = current_source(&peers, other_addr);
    let frontier = sync.observe_frontier(sync.observe_chain_frontier(), Instant::now());

    assert_eq!(
        sync.probe_frontier_peer(&frontier, frontier_source),
        GetheadersOutcome::Sent,
    );
    assert!(matches!(frontier_rx.try_recv()?, Message::GetHeaders(_)));
    {
        let mut scheduler = sync.scheduler.lock();
        let request = scheduler
            .headers_sync
            .get_mut(&frontier_source)
            .and_then(|owned| owned.request.as_mut())
            .ok_or("the frontier request must be registered")?;
        assert_eq!(request.kind, super::super::HeaderRequestKind::Frontier,);
        request.requested_at = Instant::now()
            .checked_sub(request.timeout())
            .ok_or("the frontier request must be expired")?;
    }

    assert!(sync.probe_chain_sync(frontier_source, &frontier));
    assert!(matches!(frontier_rx.try_recv()?, Message::GetHeaders(_)));
    let probe_snapshot = {
        let scheduler = sync.scheduler.lock();
        assert_eq!(scheduler.header_request_owner, None);
        assert!(scheduler.header_request().is_none());
        let request = scheduler
            .headers_sync
            .get(&frontier_source)
            .and_then(|owned| owned.request)
            .ok_or("the unanswered chain-sync probe must remain registered")?;
        assert_eq!(
            (request.kind, request.state),
            (
                super::super::HeaderRequestKind::ChainSyncProbe,
                super::super::HeaderRequestState::AwaitingResponse,
            ),
        );
        (
            request.locator_tip_hash,
            request.target_height,
            request.requested_at,
            request.state,
            request.kind,
        )
    };

    assert_eq!(
        sync.send_getheaders(other_source, 0, i32::MAX, vec![Hash256::default()]),
        GetheadersOutcome::Sent,
    );
    assert!(matches!(other_rx.try_recv()?, Message::GetHeaders(_)));
    let scheduler = sync.scheduler.lock();
    assert_eq!(
        scheduler.header_request_owner,
        Some(other_source),
        "frontier pacing must move off the connection now owned by the probe",
    );
    assert_eq!(
        scheduler.header_request().map(|request| request.source),
        Some(other_source),
    );
    let request = scheduler
        .headers_sync
        .get(&frontier_source)
        .and_then(|owned| owned.request)
        .ok_or("the probe must remain outstanding")?;
    assert_eq!(
        (
            request.locator_tip_hash,
            request.target_height,
            request.requested_at,
            request.state,
            request.kind,
        ),
        probe_snapshot,
    );
    Ok(())
}

#[test]
fn empty_chain_sync_probe_keeps_original_five_second_pacing() -> TestResult {
    let (tree, _blocks) = mined_chain(1, 2)?;
    let harness = SyncHarness::new(tree);
    let sync = harness.sync;
    let peers = harness.peers;
    let inbound_headers_tx = harness.inbound_headers_tx;
    sync.chain.bootstrap_genesis();

    let addr = test_addr(9_945, 0)?;
    let rx = connect_peer(&peers, synthetic_peer(addr, i32::MAX));
    let source = current_source(&peers, addr);
    let frontier = sync.observe_frontier(sync.observe_chain_frontier(), Instant::now());
    assert!(sync.probe_chain_sync(source, &frontier));
    assert!(matches!(rx.try_recv()?, Message::GetHeaders(_)));

    let original_request = sync
        .scheduler
        .lock()
        .headers_sync
        .get(&source)
        .and_then(|owned| owned.request)
        .ok_or("the chain-sync request must be registered")?;
    assert_eq!(
        (original_request.kind, original_request.state),
        (
            super::super::HeaderRequestKind::ChainSyncProbe,
            super::super::HeaderRequestState::AwaitingResponse,
        ),
    );
    assert_eq!(
        original_request.timeout(),
        HEADERS_RESPONSE_TIME,
        "only an unanswered probe uses the eviction response window",
    );

    inbound_headers_tx.send(crate::InboundHeaders {
        headers: Vec::new(),
        source: Some(source),
        wire_response: true,
        body_fetch_owned: false,
    })?;
    sync.drain_inbound_headers();

    let answered_request = sync
        .scheduler
        .lock()
        .headers_sync
        .get(&source)
        .and_then(|owned| owned.request)
        .ok_or("an empty answer retains the pacing request")?;
    assert_eq!(
        answered_request.state,
        super::super::HeaderRequestState::Answered,
    );
    assert_eq!(answered_request.requested_at, original_request.requested_at);
    assert_eq!(
        answered_request.timeout(),
        super::super::HEADER_REQUEST_TIMEOUT,
        "an empty answer returns to ordinary frontier pacing",
    );
    let locator = vec![answered_request.locator_tip_hash];
    let target = i32::try_from(answered_request.target_height).unwrap_or(i32::MAX);
    assert_eq!(
        sync.send_getheaders(source, 0, target, locator.clone()),
        GetheadersOutcome::Suppressed,
    );
    assert!(rx.try_recv().is_err());

    let request_age = answered_request
        .timeout()
        .checked_add(Duration::from_secs(1))
        .ok_or("the test age must fit in a duration")?;
    assert!(request_age < HEADERS_RESPONSE_TIME);
    let expired_at = Instant::now()
        .checked_sub(request_age)
        .ok_or("the test instant must allow the answered age")?;
    {
        let mut scheduler = sync.scheduler.lock();
        scheduler
            .headers_sync
            .get_mut(&source)
            .and_then(|owned| owned.request.as_mut())
            .ok_or("the answered request must remain registered")?
            .requested_at = expired_at;
    }
    sync.retire_timed_out_header_syncs(Instant::now());
    let retained_request = sync
        .scheduler
        .lock()
        .headers_sync
        .get(&source)
        .and_then(|owned| owned.request)
        .ok_or("an answered request is not a silence timeout")?;
    assert_eq!(
        retained_request.state,
        super::super::HeaderRequestState::Answered
    );
    assert_eq!(retained_request.requested_at, expired_at);
    assert_eq!(
        sync.send_getheaders(source, 0, target, locator),
        GetheadersOutcome::Sent,
    );
    assert!(matches!(rx.try_recv()?, Message::GetHeaders(_)));
    Ok(())
}

#[test]
fn expired_chain_sync_probe_does_not_suppress_frontier_request() -> TestResult {
    let (tree, _blocks) = mined_chain(1, 2)?;
    let harness = SyncHarness::new(tree);
    let sync = harness.sync;
    let peers = harness.peers;
    sync.chain.bootstrap_genesis();

    let addr = test_addr(9_941, 0)?;
    let rx = connect_peer(&peers, synthetic_peer(addr, i32::MAX));
    let source = current_source(&peers, addr);
    let frontier = sync.observe_frontier(sync.observe_chain_frontier(), Instant::now());
    assert!(sync.probe_chain_sync(source, &frontier));
    assert!(matches!(rx.try_recv()?, Message::GetHeaders(_)));

    {
        let mut scheduler = sync.scheduler.lock();
        let request = scheduler
            .headers_sync
            .get_mut(&source)
            .and_then(|owned| owned.request.as_mut())
            .ok_or("the eviction request must be registered")?;
        assert_eq!(
            request.kind,
            super::super::HeaderRequestKind::ChainSyncProbe,
        );
        request.requested_at = Instant::now()
            .checked_sub(HEADERS_RESPONSE_TIME)
            .ok_or("the test instant must allow the full response window")?;
    }

    assert_eq!(
        sync.send_getheaders(source, 0, 1, vec![Hash256::default()]),
        GetheadersOutcome::Sent,
        "an expired response window must release the request gate",
    );
    assert!(matches!(rx.try_recv()?, Message::GetHeaders(_)));
    let scheduler = sync.scheduler.lock();
    let request_kind = scheduler
        .headers_sync
        .get(&source)
        .and_then(|owned| owned.request)
        .map(|request| request.kind);
    assert_eq!(
        request_kind,
        Some(super::super::HeaderRequestKind::Frontier),
    );
    Ok(())
}

#[test]
#[expect(clippy::expect_used)]
fn a_failed_sweep_probe_restores_the_armed_record() {
    let t0 = Instant::now();
    let (tree, _blocks) = mined_chain(1, 1).expect("chain fixture builds");
    let SyncHarness { sync, peers, .. } = SyncHarness::new(tree);
    sync.chain.bootstrap_genesis();

    let addr = test_addr(9_920, 0).expect("test address");
    let (tx, rx) = unbounded::<Message>();
    let connected_at = t0
        .checked_sub(MINIMUM_CONNECT_TIME)
        .expect("the test clock predates the connect age");
    let lease = PeerLease::new_connected_at(tx, connected_at);
    peers.register(addr, lease.clone());
    peers.publish_info(addr, &lease, synthetic_peer(addr, 0));
    let source = current_source(&peers, addr);

    let frontier = sync.observe_frontier(sync.observe_chain_frontier(), t0);
    sync.sweep_chain_sync(&frontier, t0);
    {
        let scheduler = sync.scheduler.lock();
        let state = scheduler
            .chain_sync
            .get(&source)
            .expect("the first sweep arms the lagging claimant");
        assert!(
            !state.probe_sent(),
            "an armed window has not yet owed a probe"
        );
    }

    drop(rx);
    let stale = sync.observe_frontier(sync.observe_chain_frontier(), t0);
    sync.sweep_chain_sync(&stale, t0 + Duration::from_mins(20));

    let scheduler = sync.scheduler.lock();
    let state = scheduler
        .chain_sync
        .get(&source)
        .expect("a failed probe restores the armed record rather than advancing it");
    assert!(
        !state.probe_sent(),
        "the probe never reached the wire, so no response window is running"
    );
}
