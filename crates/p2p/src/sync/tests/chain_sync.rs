//! Chain-sync eviction: the twenty-minute timeout, the one probe that ends
//! it, the two-minute response window, and the protection that spares the
//! first four outbound connections to reach the tip.

use std::time::Duration;

use super::*;
use crate::download_window::MINIMUM_CONNECT_TIME;
use crate::peer_info::PeerRole;
use crate::sync::GetheadersOutcome;
use crate::sync::frontier::UsablePeer;
use crate::sync::peers::{ChainSyncAction, ChainSyncState, chain_sync_subject, consider_eviction};

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

/// A handshake claim of the tip height is not evidence. Core protects and
/// clears only from `pindexBestKnownBlock`, a tip the peer actually sent
/// (`net_processing.cpp:3203-3210`), so a silent claimant is armed like any
/// other lagging outbound connection and answers to the timer.
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

/// A connection that never brings a better chain is probed once at the
/// timeout and retired one response window later.
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

/// A connection that reaches the tip is protected for the life of the
/// connection, even after the tip moves away from it.
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

    // The network moves on and this connection stops contributing.
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

/// Only the first four tip-reaching connections are spared; the next one is
/// timed out like any other.
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

/// The rule applies to aged outbound full-relay connections only.
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

/// Progress to the benchmark recorded at arming restarts the window, even
/// while our own tip has moved past it: Core re-arms when the peer reaches
/// `m_work_header` (`net_processing.cpp:5519-5527`).
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

    // The peer delivers the tip we had at arming; ours has moved to 150.
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

/// The response window starts only on a probe the connection was actually
/// asked to answer. The chain-sync probe ignores frontier body ownership —
/// the lagging peer owes an answer for its own silence — so the fixture's
/// owned frontier does not suppress the send; the unregistered fixture
/// connection fails the send instead, and the sweep must still restore the
/// record untouched so the connection cannot be retired for ignoring a
/// request it never received, and the operator counter does not count the
/// silence as a probe.
#[test]
#[expect(clippy::expect_used)]
fn an_unsent_chain_sync_probe_arms_no_response_window() {
    let t0 = Instant::now();
    // A mined tree whose tip is one header past the last body: the frontier
    // owes a body, and genesis is applied so the probes below have tips and
    // a locator to build from.
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
    // Own the frontier body: pending in the window, so nothing may be sent.
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

/// The eviction benchmark is taken from the header tip, so the probe's
/// locator anchors at the best header's parent — an applied-tip anchor
/// cannot return the header tip while IBD lags a page behind it, and a
/// correct answer would credit only the applied side.
#[test]
#[expect(clippy::expect_used)]
fn chain_sync_probe_locator_anchors_at_the_header_tips_parent() {
    let t0 = Instant::now();
    // Bodies to 1, headers to 3, genesis applied: the applied anchor sits
    // two headers under the benchmark.
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

/// The sweep-level guarantee for the same contract
/// `a_probe_that_never_reached_the_wire_is_not_a_probe` checks on
/// `probe_chain_sync`: when the sweep's probe send fails — the lease's queue
/// is gone — the connection's record is put back exactly as the sweep found
/// it, so the next tick retries instead of holding a response window against
/// a request that never arrived.
#[test]
#[expect(clippy::expect_used)]
fn a_failed_sweep_probe_restores_the_armed_record() {
    let t0 = Instant::now();
    let (tree, _blocks) = mined_chain(1, 1).expect("chain fixture builds");
    let SyncHarness { sync, peers, .. } = SyncHarness::new(tree);
    sync.chain.bootstrap_genesis();

    let addr = test_addr(9_920, 0).expect("test address");
    let (tx, rx) = unbounded::<Message>();
    // Old enough that the connection is a chain-sync subject on every tick.
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

    // Kill the connection's outbound queue so the probe send must fail.
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
