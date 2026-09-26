//! Chain-sync eviction: the twenty-minute timeout, the one probe that ends
//! it, the two-minute response window, and the protection that spares the
//! first four outbound connections to reach the tip.

use std::time::Duration;

use super::*;
use crate::peer_info::PeerRole;
use crate::sync::frontier::UsablePeer;
use crate::sync::peers::{ChainSyncAction, ChainSyncState, chain_sync_subject, consider_eviction};

use crate::download_window::MINIMUM_CONNECT_TIME;

/// An outbound connection that demonstrated `height`.
fn outbound(port: u16, height: u32, role: PeerRole, at: Instant) -> UsablePeer {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    UsablePeer {
        source: PeerSource::for_test(addr),
        info: synthetic_peer(addr, i32::try_from(height).unwrap_or(i32::MAX)),
        demonstrated_tips: vec![Hash256::from_le_bytes(&[0x7c; 32])],
        active_height: Some(height),
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
