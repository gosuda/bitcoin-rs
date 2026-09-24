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

/// The network's target spacing: ten minutes, as every production chain
/// configures it.
const SPACING: Duration = Duration::from_secs(600);

/// The armed allowance must let the connection manager dial past the slot
/// cap, or the stale-tip rule buys nothing: Core's `ThreadOpenConnections`
/// opens one more full-relay peer while `GetTryNewOutboundPeer()` is set
/// (`net.cpp:2786-2806`), on top of the full and block-relay populations.
#[test]
#[expect(
    clippy::expect_used,
    reason = "a test that cannot wire its fake peers has nothing to report"
)]
fn the_stale_tip_allowance_dials_past_the_slot_cap() {
    // A scheduler whose tip has stood still for three target spacings.
    let t0 = Instant::now();
    let tree = BlockTree::new();
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
        Arc::new(Mutex::new(headers_rx)),
        Arc::new(Mutex::new(blocks_rx)),
    ));
    {
        let mut scheduler = sync.scheduler.lock();
        scheduler.stale_tip.follow(100, 0, SPACING, t0);
        scheduler
            .stale_tip
            .follow(100, 0, SPACING, t0 + Duration::from_mins(35));
    }
    assert!(
        sync.allow_extra_full_relay_dial(),
        "premise: the stale tip armed the extra dial"
    );

    // A service with one full-relay and one block-relay slot, so the cap is
    // two and the third dial only forms on the allowance.
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

    // Three pinned addresses: two fill the slots, the third may only dial
    // because the stale tip raises the cap by one.
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
        service.add_node(addr, false).expect("queue the dial");
    }

    let mut held = Vec::new();
    for (index, listener) in listeners.iter().enumerate() {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match listener.accept() {
                Ok((stream, _peer)) => {
                    // The stream stays alive: the connection thread then sits
                    // in its one-minute handshake, holding its slot.
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

    // Closing the sockets lets each connection thread see EOF and exit, so
    // the drain worker's final join cannot hang.
    drop(held);
    drop(listeners);
    service.shutdown();
    service.join().expect("clean join");
}

/// A tip that stands still for three target spacings buys one extra dial, and
/// the next advance takes the allowance back at once.
#[test]
fn still_tip_buys_one_extra_dial_and_an_advance_withdraws_it() {
    let t0 = Instant::now();
    let mut state = StaleTipState::default();

    state.follow(100, 0, SPACING, t0);
    assert!(
        !state.extra_dial_allowed,
        "the first sight of a tip is progress, not staleness"
    );

    state.follow(100, 0, SPACING, t0 + Duration::from_mins(29));
    assert!(
        !state.extra_dial_allowed,
        "twenty-nine minutes of standing still is inside the bound"
    );

    state.follow(100, 0, SPACING, t0 + Duration::from_mins(40));
    assert!(
        state.extra_dial_allowed,
        "three intervals without a tip move is a stale tip"
    );

    state.follow(101, 0, SPACING, t0 + Duration::from_mins(41));
    assert!(
        !state.extra_dial_allowed,
        "an advancing tip withdraws the allowance without waiting for the next check"
    );
}

/// The staleness question is asked once per `STALE_CHECK_INTERVAL`, so a tip
/// crossing the three-interval bound between two checks is not judged until the
/// next one is due.
#[test]
fn the_staleness_question_is_paced() {
    let t0 = Instant::now();
    let mut state = StaleTipState::default();
    state.follow(100, 0, SPACING, t0);

    // Twenty-five minutes: the question is asked and answered "not yet", and
    // the next answer is not due until ten minutes later.
    state.follow(100, 0, SPACING, t0 + Duration::from_mins(25));
    assert!(!state.extra_dial_allowed, "inside the bound");
    state.follow(100, 0, SPACING, t0 + Duration::from_mins(31));
    assert!(
        !state.extra_dial_allowed,
        "past the bound but not yet due for a check"
    );
    state.follow(100, 0, SPACING, t0 + Duration::from_mins(35));
    assert!(
        state.extra_dial_allowed,
        "the check that is due finds the tip stale"
    );
}

/// Three target spacings of silence is the bound, and nothing in flight is the
/// other half of it.
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
