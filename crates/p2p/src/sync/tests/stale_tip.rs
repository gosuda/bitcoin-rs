use std::io;
use std::net::TcpListener;
use std::sync::atomic::AtomicBool;
use std::thread;

use super::super::stale_tips::{MAX_ADVERTISED_STALETIPS, StaleTipRetainer};
use super::super::{StaleTipState, tip_may_be_stale};
use super::*;
use crate::listener::ListenerExtras;
use crate::service::{P2pService, P2pServiceConfig};
use bitcoin_rs_primitives::Hash256;

const SPACING: Duration = Duration::from_mins(10);

const GENESIS_HASH: Hash256 = Hash256::from_le_bytes(&[7u8; 32]);

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
            let listener =
                TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind a fake peer listener");
            listener
                .set_nonblocking(true)
                .expect("nonblocking fake peer listener");
            listener
        })
        .collect();
    for listener in &listeners {
        let addr = listener.local_addr().expect("fake peer address");
        service
            .test_queue_automatic_dial(addr.into())
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
type TestError = Box<dyn std::error::Error>;

struct RetainerFixture {
    tree: BlockTree,
    genesis: NodeId,
    salt: u32,
}

impl RetainerFixture {
    fn new() -> Result<Self, TestError> {
        let mut tree = BlockTree::new();
        let genesis = tree.insert_node(
            None,
            Network::Regtest.genesis_block().header,
            NodeStatus::HeaderValid,
        )?;
        Ok(Self {
            tree,
            genesis,
            salt: 1,
        })
    }

    fn id(&self, hash: Hash256) -> Result<NodeId, TestError> {
        self.tree
            .lookup(hash)
            .ok_or_else(|| "an admitted hash is missing from the tree".into())
    }

    fn child(&mut self, parent: NodeId) -> Result<Hash256, TestError> {
        let prev = self.tree.node(parent)?.hash;
        self.salt += 1;
        let header = regtest_fixture::mined_regtest_header(BlockHash::from(prev), self.salt)?;
        let id = self
            .tree
            .insert_node(Some(parent), header, NodeStatus::HeaderValid)?;
        Ok(self.tree.node(id)?.hash)
    }

    fn branch(&mut self, from: NodeId, len: usize) -> Result<Vec<Hash256>, TestError> {
        let mut hashes = Vec::with_capacity(len);
        let mut parent = from;
        for _ in 0..len {
            let hash = self.child(parent)?;
            parent = self.id(hash)?;
            hashes.push(hash);
        }
        Ok(hashes)
    }

    fn main_chain(&mut self, len: usize) -> Result<Vec<Hash256>, TestError> {
        let genesis = self.genesis;
        self.branch(genesis, len)
    }
}

fn retainer_peer(port: u16) -> PeerSource {
    PeerSource::for_test(SocketAddr::from(([127, 0, 0, 1], port)))
}

#[test]
fn a_refused_initial_tip_stays_offerable_until_sent_or_retired() -> Result<(), TestError> {
    let mut fixture = RetainerFixture::new()?;
    let main = fixture.main_chain(20)?;
    let side = fixture.branch(fixture.id(main[9])?, 2)?;
    let tip = side[1];
    let retainer = StaleTipRetainer::default();
    assert!(retainer.learn(&fixture.tree, tip, None));
    let peer = retainer_peer(41);

    assert_eq!(retainer.pending_for(peer, |_| false), Vec::<Hash256>::new());
    assert_eq!(retainer.pending_for(peer, |_| true), vec![tip]);
    assert_eq!(
        retainer.pending_for(peer, |hash| hash != tip),
        Vec::<Hash256>::new()
    );
    assert_eq!(retainer.pending_for(peer, |_| true), vec![tip]);
    retainer.mark_known(peer, tip);
    assert!(retainer.knows(peer, tip));
    assert_eq!(retainer.pending_for(peer, |_| true), Vec::<Hash256>::new());
    Ok(())
}

#[test]
fn multiple_refused_initial_tips_retry_in_rank_order() -> Result<(), TestError> {
    let mut fixture = RetainerFixture::new()?;
    let main = fixture.main_chain(20)?;
    let fork = fixture.id(main[9])?;
    let first = fixture.child(fork)?;
    let second = fixture.child(fork)?;
    let third = fixture.child(fork)?;
    let retainer = StaleTipRetainer::default();
    assert!(retainer.learn(&fixture.tree, first, None));
    assert!(retainer.learn(&fixture.tree, second, None));
    assert!(retainer.learn(&fixture.tree, third, None));
    let peer = retainer_peer(42);

    let opening = retainer.pending_for(peer, |hash| hash == first);
    assert_eq!(opening, vec![first]);
    assert_eq!(
        retainer.pending_for(peer, |_| true),
        vec![third, second, first]
    );
    for hash in [third, second, first] {
        retainer.mark_known(peer, hash);
    }
    assert_eq!(retainer.pending_for(peer, |_| true), Vec::<Hash256>::new());
    Ok(())
}

#[test]
fn deferred_initial_tips_never_exceed_the_opening_cap() -> Result<(), TestError> {
    let mut fixture = RetainerFixture::new()?;
    let main = fixture.main_chain(100)?;
    let fork = fixture.id(main[49])?;
    let retainer = StaleTipRetainer::default();
    let mut leaves = Vec::new();
    for _ in 0..MAX_ADVERTISED_STALETIPS + 3 {
        let leaf = fixture.child(fork)?;
        assert!(retainer.learn(&fixture.tree, leaf, None));
        leaves.push(leaf);
    }
    let peer = retainer_peer(43);

    assert_eq!(retainer.pending_for(peer, |_| false), Vec::<Hash256>::new());
    let mut expected = leaves[3..].to_vec();
    expected.reverse();
    let retry = retainer.pending_for(peer, |_| true);
    assert_eq!(retry.len(), MAX_ADVERTISED_STALETIPS);
    assert_eq!(retry, expected);
    for hash in &leaves[..3] {
        assert!(!retry.contains(hash));
    }
    for hash in &retry {
        retainer.mark_known(peer, *hash);
    }
    assert_eq!(retainer.pending_for(peer, |_| true), Vec::<Hash256>::new());
    Ok(())
}

#[test]
fn known_sent_and_retired_tips_leave_the_deferred_backlog() -> Result<(), TestError> {
    let mut fixture = RetainerFixture::new()?;
    let main = fixture.main_chain(20)?;
    let tip = fixture.child(fixture.id(main[9])?)?;
    let retainer = StaleTipRetainer::default();

    let origin = retainer_peer(44);
    assert!(retainer.learn(&fixture.tree, tip, Some(origin)));
    assert_eq!(
        retainer.pending_for(origin, |_| true),
        Vec::<Hash256>::new()
    );

    let peer = retainer_peer(45);
    assert_eq!(retainer.pending_for(peer, |_| false), Vec::<Hash256>::new());
    assert_eq!(retainer.pending_for(peer, |_| true), vec![tip]);
    retainer.mark_known(peer, tip);
    assert_eq!(retainer.pending_for(peer, |_| true), Vec::<Hash256>::new());

    let late = retainer_peer(46);
    assert_eq!(retainer.pending_for(late, |_| false), Vec::<Hash256>::new());
    retainer.forget_peer(late);
    assert_eq!(retainer.pending_for(late, |_| true), vec![tip]);
    retainer.mark_known(late, tip);
    assert_eq!(retainer.pending_for(late, |_| true), Vec::<Hash256>::new());

    fixture.tree.invalidate_subtree(fixture.id(tip)?)?;
    retainer.prune(&fixture.tree);
    let last = retainer_peer(47);
    assert_eq!(retainer.pending_for(last, |_| true), Vec::<Hash256>::new());
    Ok(())
}

#[test]
fn eligible_initial_offer_without_send_ack_is_offered_again() -> Result<(), TestError> {
    let mut fixture = RetainerFixture::new()?;
    let main = fixture.main_chain(20)?;
    let tip = fixture.child(fixture.id(main[9])?)?;
    let retainer = StaleTipRetainer::default();
    assert!(retainer.learn(&fixture.tree, tip, None));
    let peer = retainer_peer(48);

    assert_eq!(retainer.pending_for(peer, |_| true), vec![tip]);
    assert!(
        !retainer.knows(peer, tip),
        "offering is not delivery: no send-Ok, no mark"
    );
    assert_eq!(retainer.pending_for(peer, |_| true), vec![tip]);
    retainer.mark_known(peer, tip);
    assert_eq!(retainer.pending_for(peer, |_| true), Vec::<Hash256>::new());
    Ok(())
}

#[test]
fn saturated_batch_tail_retries_only_the_unacked_remainder() -> Result<(), TestError> {
    let mut fixture = RetainerFixture::new()?;
    let main = fixture.main_chain(20)?;
    let fork = fixture.id(main[9])?;
    let first = fixture.child(fork)?;
    let second = fixture.child(fork)?;
    let third = fixture.child(fork)?;
    let retainer = StaleTipRetainer::default();
    assert!(retainer.learn(&fixture.tree, first, None));
    assert!(retainer.learn(&fixture.tree, second, None));
    assert!(retainer.learn(&fixture.tree, third, None));
    let peer = retainer_peer(49);

    let opening = retainer.pending_for(peer, |_| true);
    assert_eq!(opening, vec![third, second, first]);
    retainer.mark_known(peer, third);

    assert_eq!(retainer.pending_for(peer, |_| true), vec![second, first]);
    assert_eq!(retainer.pending_for(peer, |_| false), Vec::<Hash256>::new());
    assert_eq!(retainer.pending_for(peer, |_| true), vec![second, first]);
    retainer.mark_known(peer, second);
    retainer.mark_known(peer, first);
    assert_eq!(retainer.pending_for(peer, |_| true), Vec::<Hash256>::new());
    Ok(())
}
