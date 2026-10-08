//! Stale-tip policy: the one extra full-relay dial a stalled tip buys, and
//! the conditions that refuse it.

use std::io;
use std::net::TcpListener;
use std::sync::atomic::AtomicBool;
use std::thread;

use super::super::{StaleTipState, tip_may_be_stale};
use super::*;
use crate::listener::ListenerExtras;
use crate::service::{P2pService, P2pServiceConfig};
use bitcoin_rs_primitives::Hash256;

/// The network's target spacing: ten minutes, as every production chain
/// configures it.
const SPACING: Duration = Duration::from_mins(10);

/// A stand-in tip hash for staleness fixtures; only identity matters.
const GENESIS_HASH: Hash256 = Hash256::from_le_bytes(&[7u8; 32]);

/// A second stand-in tip hash at the same height as [`GENESIS_HASH`].
const REPLACEMENT_HASH: Hash256 = Hash256::from_le_bytes(&[9u8; 32]);

#[test]
#[expect(
    clippy::expect_used,
    reason = "a test that cannot wire its fake peers has nothing to report"
)]
fn the_stale_tip_allowance_dials_past_the_slot_cap() {
    let t0 = Instant::now();
    let mut tree = BlockTree::new();
    let chain_tip = tree.tip_handle();
    let (_headers_tx, headers_rx) = unbounded();
    let (_blocks_tx, blocks_rx) = unbounded();
    let chain: Arc<dyn SyncChain> = Arc::new(TestChain::new(
        chain_tip,
        Arc::new(ArcSwapOption::empty()),
        Arc::new(RwLock::new(tree)),
    ));
    let sync = Arc::new(BlockSync::new(
        chain,
        Arc::new(PeerTable::new()),
        headers_rx,
        blocks_rx,
        crate::sync::syncing_ibd_latch(),
    ));
    {
        let mut scheduler = sync.scheduler.lock();
        scheduler
            .stale_tip
            .follow(100, GENESIS_HASH, 0, SPACING, t0);
        scheduler
            .stale_tip
            .follow(100, GENESIS_HASH, 0, SPACING, t0 + Duration::from_mins(35));
    }
    assert!(
        sync.allow_extra_full_relay_dial(),
        "premise: the stale tip armed the extra dial"
    );

    let service = P2pService::new(
        P2pServiceConfig {
            listen_addrs: Vec::new(),
            outbound_full_relay_slots: 1,
            outbound_block_relay_slots: 1,
            ..P2pServiceConfig::default()
        },
        Arc::new(AtomicBool::new(false)),
    );
    let ready: Arc<dyn Fn(PeerSource) + Send + Sync> = Arc::new(|_| {});
    service
        .start(
            None,
            None,
            &ready,
            ListenerExtras {
                block_sync: Some(Arc::clone(&sync)),
                ..ListenerExtras::default()
            },
        )
        .expect("the service starts");

    let listeners: Vec<TcpListener> = (0..3)
        .map(|_| {
            let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                .expect("bind a fake peer listener");
            listener
                .set_nonblocking(true)
                .expect("nonblocking fake peer listener");
            listener
        })
        .collect();
    for listener in &listeners {
        let addr = listener.local_addr().expect("fake peer address");
        service
            .test_queue_automatic_dial(addr)
            .expect("queue the automatic dial");
    }

    let mut held = Vec::new();
    for (index, listener) in listeners.iter().enumerate() {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match listener.accept() {
                Ok((stream, _peer)) => {
                    held.push(stream);
                    break;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    assert!(
                        Instant::now() < deadline,
                        "dial {index} never arrived: the drain loop capped at the un-raised slot total"
                    );
                    thread::sleep(Duration::from_millis(20));
                }
                Err(error) => panic!("accept failed: {error}"),
            }
        }
    }
    assert_eq!(
        held.len(),
        3,
        "all three dials arrived and hold their slots"
    );

    drop(held);
    drop(listeners);
    service.shutdown();
    service.join().expect("clean join");
}

#[test]
fn still_tip_buys_one_extra_dial_and_an_advance_withdraws_it() {
    let t0 = Instant::now();
    let mut state = StaleTipState::default();

    state.follow(100, GENESIS_HASH, 0, SPACING, t0);
    assert!(
        !state.extra_dial_allowed,
        "the first sight of a tip is progress, not staleness"
    );

    state.follow(100, GENESIS_HASH, 0, SPACING, t0 + Duration::from_mins(29));
    assert!(
        !state.extra_dial_allowed,
        "twenty-nine minutes of standing still is inside the bound"
    );

    state.follow(100, GENESIS_HASH, 0, SPACING, t0 + Duration::from_mins(40));
    assert!(
        state.extra_dial_allowed,
        "three intervals without a tip move is a stale tip"
    );

    state.follow(101, GENESIS_HASH, 0, SPACING, t0 + Duration::from_mins(41));
    assert!(
        !state.extra_dial_allowed,
        "an advancing tip withdraws the allowance without waiting for the next check"
    );
}

#[test]
fn a_same_height_tip_change_restarts_the_staleness_clock() {
    let t0 = Instant::now();
    let mut state = StaleTipState::default();

    state.follow(100, GENESIS_HASH, 0, SPACING, t0);
    state.follow(100, GENESIS_HASH, 0, SPACING, t0 + Duration::from_mins(40));
    assert!(
        state.extra_dial_allowed,
        "premise: the stood-still tip armed the extra dial"
    );

    state.follow(
        100,
        REPLACEMENT_HASH,
        0,
        SPACING,
        t0 + Duration::from_mins(41),
    );
    assert!(
        !state.extra_dial_allowed,
        "a same-height tip change withdraws the allowance at once"
    );

    state.follow(
        100,
        REPLACEMENT_HASH,
        0,
        SPACING,
        t0 + Duration::from_mins(69),
    );
    assert!(
        !state.extra_dial_allowed,
        "the next check finds the new tip only 28 minutes old, inside the bound"
    );

    state.follow(99, GENESIS_HASH, 0, SPACING, t0 + Duration::from_mins(71));
    assert!(
        !state.extra_dial_allowed,
        "a reorg to a lower tip withdraws the allowance at once"
    );
    state.follow(99, GENESIS_HASH, 0, SPACING, t0 + Duration::from_mins(82));
    assert!(
        !state.extra_dial_allowed,
        "the due check finds the reorganized tip only 11 minutes old, inside the bound"
    );
    state.follow(99, GENESIS_HASH, 0, SPACING, t0 + Duration::from_mins(102));
    assert!(
        state.extra_dial_allowed,
        "the next due check finds 31 minutes of stillness on the reorganized tip: stale"
    );
}

#[test]
fn the_staleness_question_is_paced() {
    let t0 = Instant::now();
    let mut state = StaleTipState::default();
    state.follow(100, GENESIS_HASH, 0, SPACING, t0);

    state.follow(100, GENESIS_HASH, 0, SPACING, t0 + Duration::from_mins(25));
    assert!(!state.extra_dial_allowed, "inside the bound");
    state.follow(100, GENESIS_HASH, 0, SPACING, t0 + Duration::from_mins(31));
    assert!(
        !state.extra_dial_allowed,
        "past the bound but not yet due for a check"
    );
    state.follow(100, GENESIS_HASH, 0, SPACING, t0 + Duration::from_mins(35));
    assert!(
        state.extra_dial_allowed,
        "the check that is due finds the tip stale"
    );
}

#[test]
fn in_flight_bodies_hold_staleness_off() {
    let t0 = Instant::now();
    let mut state = StaleTipState {
        last_update: Some(t0),
        ..StaleTipState::default()
    };

    assert!(
        !tip_may_be_stale(&mut state, 0, SPACING, t0 + Duration::from_mins(30)),
        "exactly three intervals is not past the bound"
    );
    assert!(
        tip_may_be_stale(&mut state, 0, SPACING, t0 + Duration::from_mins(31)),
        "past three intervals with nothing in flight the tip is stale"
    );
    assert!(
        !tip_may_be_stale(&mut state, 4, SPACING, t0 + Duration::from_mins(31)),
        "bodies still arriving is progress, not a stalled tip"
    );
}
