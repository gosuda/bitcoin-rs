//! #1128 model/property coverage: the canonical frontier reconciler's
//! invariant over `SyncFrontier::plan`, exercised directly against
//! synthesized frontier states, plus the connection-identity pins that
//! close the same-address-replacement race the issue's prior attempt
//! left open.

use super::*;

use super::super::frontier::{
    BodyState, ChainFrontier, HeaderAction, NoProgressReason, RequiredBody, SyncFrontier,
    UsablePeer,
};
use crate::BlockStager;
use crate::download_window::{BlameReason, BlockedContext, BlockedDecision, DownloadWindow};
use bitcoin_rs_chain::{ChainWork, NodeId};

/// Advances the unified blockage observation one tick and returns the
/// stall blame's owner, if this tick convicted one.
fn stall_blame(
    window: &mut DownloadWindow,
    stager: &BlockStager,
    tree: &bitcoin_rs_chain::BlockTree,
    next_apply: u32,
    at: Instant,
) -> Option<PeerSource> {
    match window.observe_blocked(
        BlockedContext {
            next_apply_height: Some(next_apply),
            frontier_hash: None,
            apply_side_busy: false,
            active_downloading_peers: window.active_downloading_peers(),
        },
        stager,
        tree,
        at,
    ) {
        BlockedDecision::Blame {
            owner,
            reason: BlameReason::Staller,
        } => Some(owner),
        _ => None,
    }
}
fn snap(tip_id: u32, height: u32, hash_byte: u8) -> Arc<TipSnapshot> {
    Arc::new(TipSnapshot {
        tip_id: NodeId::new(tip_id),
        height,
        chainwork: ChainWork::from(u64::from(height) + 1),
        hash: Hash256::from_le_bytes(&[hash_byte; 32]),
    })
}

fn hash(byte: u8) -> Hash256 {
    Hash256::from_le_bytes(&[byte; 32])
}

fn addr_of(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
}

fn usable(port: u16, best_known: i32, active_height: Option<u32>) -> UsablePeer {
    UsablePeer {
        source: PeerSource::for_test(addr_of(port)),
        info: synthetic_peer(addr_of(port), best_known),
        demonstrated_tips: Vec::new(),
        active_height,
        role: crate::peer_info::PeerRole::FullRelay,
        manual: false,
        connected_at: Instant::now(),
    }
}

/// A diverged chain (`applied` at 0x01, `chain` tip at 0x02) requiring the
/// body at `required_height`.
fn chain_frontier(required_height: u32, apply_halted: bool) -> ChainFrontier {
    ChainFrontier {
        applied_tip: Some(snap(1, required_height.saturating_sub(1), 0x01)),
        chain_tip: Some(snap(2, required_height + 4, 0x02)),
        next_required: Some(RequiredBody {
            height: required_height,
            hash: hash(0x03),
        }),
        apply_halted,
    }
}

fn frontier(
    chain: ChainFrontier,
    body_state: Option<BodyState>,
    usable_peers: Vec<UsablePeer>,
) -> SyncFrontier {
    SyncFrontier {
        chain,
        body_state,
        header_request: None,
        header_request_live: false,
        usable_peers,
    }
}

/// The issue's invariant in one place: whenever a next-required body
/// exists and recovery did not run, the plan names exactly why.
fn assert_invariant(frontier: &SyncFrontier) -> super::super::frontier::FrontierPlan {
    let plan = frontier.plan();
    if frontier.chain.next_required.is_some() {
        assert!(
            plan.schedule_bodies || plan.no_progress.is_some(),
            "unowned/owned body with no scheduled recovery must carry a \
             NoProgressReason: {plan:?}"
        );
    }
    plan
}

#[test]
fn unowned_frontier_schedules_recovery_when_a_capable_peer_exists() {
    let plan = assert_invariant(&frontier(
        chain_frontier(5, false),
        Some(BodyState::Unowned),
        vec![usable(9001, 100, None)],
    ));
    assert!(plan.schedule_bodies);
    assert_eq!(plan.no_progress, None);
    match plan.header_action {
        HeaderAction::Probe(source) => assert_eq!(source.addr, addr_of(9001)),
        action => panic!("expected Probe, got {action:?}"),
    }
}

#[test]
fn unowned_frontier_with_no_peers_reports_no_usable_peers() {
    let plan = assert_invariant(&frontier(
        chain_frontier(5, false),
        Some(BodyState::Unowned),
        Vec::new(),
    ));
    assert!(!plan.schedule_bodies);
    assert_eq!(plan.no_progress, Some(NoProgressReason::NoUsablePeers));
    assert_eq!(plan.header_action, HeaderAction::Idle);
}

#[test]
fn unowned_frontier_with_only_incapable_peers_reports_no_capable_peer() {
    let plan = assert_invariant(&frontier(
        chain_frontier(5, false),
        Some(BodyState::Unowned),
        // Handshake height 2 cannot reach required height 5.
        vec![usable(9001, 2, None)],
    ));
    assert!(plan.schedule_bodies);
    assert_eq!(plan.no_progress, Some(NoProgressReason::NoCapablePeer));
}

#[test]
fn unowned_frontier_while_apply_halted_reports_apply_halted() {
    let plan = assert_invariant(&frontier(
        chain_frontier(5, true),
        Some(BodyState::Unowned),
        vec![usable(9001, 100, None)],
    ));
    assert!(!plan.schedule_bodies);
    assert_eq!(plan.no_progress, Some(NoProgressReason::ApplyHalted));
}

#[test]
fn in_flight_frontier_on_a_dead_connection_recovers_as_unowned() {
    // `InFlight(owner)` where `owner` fell out of the usable set is unowned
    // work: the plan must schedule its re-request this tick.
    let dead = PeerSource::for_test(addr_of(9010));
    let plan = assert_invariant(&frontier(
        chain_frontier(5, false),
        Some(BodyState::InFlight(dead)),
        vec![usable(9011, 100, None)],
    ));
    assert!(plan.schedule_bodies);
    assert_eq!(plan.no_progress, None);
}

#[test]
fn in_flight_frontier_on_a_live_owner_is_progress() {
    let live = usable(9010, 100, None);
    let owner = live.source;
    let plan = assert_invariant(&frontier(
        chain_frontier(5, false),
        Some(BodyState::InFlight(owner)),
        vec![live],
    ));
    assert!(plan.schedule_bodies);
    assert_eq!(plan.no_progress, None);
    assert_eq!(plan.header_action, HeaderAction::Extend);
}

#[test]
fn staged_frontier_is_progress_without_recovery() {
    let plan = assert_invariant(&frontier(
        chain_frontier(5, false),
        Some(BodyState::Staged),
        vec![usable(9001, 100, None)],
    ));
    assert!(plan.schedule_bodies);
    assert_eq!(plan.no_progress, None);
}

#[test]
fn at_tip_reports_at_tip() {
    let tip = snap(1, 7, 0x09);
    let plan = assert_invariant(&SyncFrontier {
        chain: ChainFrontier {
            applied_tip: Some(Arc::clone(&tip)),
            chain_tip: Some(tip),
            next_required: None,
            apply_halted: false,
        },
        body_state: None,
        header_request: None,
        header_request_live: false,
        usable_peers: vec![usable(9001, 100, None)],
    });
    assert!(!plan.schedule_bodies);
    assert_eq!(plan.no_progress, Some(NoProgressReason::AtTip));
}

#[test]
fn diverged_tips_with_unresolvable_frontier_report_frontier_unresolvable() {
    let plan = assert_invariant(&frontier(
        ChainFrontier {
            applied_tip: Some(snap(1, 0, 0x01)),
            chain_tip: Some(snap(2, 9, 0x02)),
            next_required: None,
            apply_halted: false,
        },
        None,
        vec![usable(9001, 100, None)],
    ));
    assert!(!plan.schedule_bodies);
    assert_eq!(
        plan.no_progress,
        Some(NoProgressReason::FrontierUnresolvable)
    );
}

#[test]
fn missing_tip_snapshot_reports_chain_view_unavailable() {
    let plan = assert_invariant(&frontier(
        ChainFrontier {
            applied_tip: None,
            chain_tip: Some(snap(2, 9, 0x02)),
            next_required: None,
            apply_halted: false,
        },
        None,
        vec![usable(9001, 100, None)],
    ));
    assert_eq!(
        plan.no_progress,
        Some(NoProgressReason::ChainViewUnavailable)
    );
}

#[test]
fn live_pending_header_request_awaits_its_connection() {
    let source = PeerSource::for_test(addr_of(9001));
    let mut frontier = frontier(
        chain_frontier(5, false),
        Some(BodyState::Unowned),
        vec![usable(9001, 100, None)],
    );
    frontier.usable_peers[0].source = source;
    frontier.header_request = Some(super::super::PendingHeaderRequest {
        source,
        locator_tip_hash: hash(0x01),
        target_height: 6,
        requested_at: Instant::now(),
        answered: false,
    });
    frontier.header_request_live = true;
    assert_eq!(frontier.plan().header_action, HeaderAction::AwaitPending);
}

#[test]
fn probe_rotates_past_the_dead_pending_owner() {
    // The pending request's connection is gone (usable_peers no longer
    // contains it), so it is not live and the probe rotates to the next
    // address past its owner.
    let dead_owner = PeerSource::for_test(addr_of(9005));
    let mut frontier = frontier(
        chain_frontier(5, false),
        Some(BodyState::Unowned),
        vec![usable(9001, 100, None), usable(9007, 100, None)],
    );
    frontier.header_request = Some(super::super::PendingHeaderRequest {
        source: dead_owner,
        locator_tip_hash: hash(0x01),
        target_height: 6,
        requested_at: Instant::now(),
        answered: false,
    });
    frontier.header_request_live = super::super::frontier::header_request_live(
        frontier.header_request,
        &frontier.usable_peers,
        Instant::now(),
    );
    assert!(!frontier.header_request_live);
    match frontier.plan().header_action {
        HeaderAction::Probe(source) => {
            assert_eq!(source.addr, addr_of(9007));
            assert_ne!(source, dead_owner);
        }
        action => panic!("expected Probe, got {action:?}"),
    }
}

#[test]
fn non_serving_peers_are_never_probe_picks() {
    let mut non_serving = usable(9001, 100, None);
    non_serving.info.services = 0;
    let frontier = frontier(
        chain_frontier(5, false),
        Some(BodyState::Unowned),
        vec![non_serving, usable(9002, 100, None)],
    );
    match frontier.plan().header_action {
        HeaderAction::Probe(source) => assert_eq!(source.addr, addr_of(9002)),
        action => panic!("expected Probe, got {action:?}"),
    }
}

proptest::proptest! {
    /// #1128's invariant as a property: across arbitrary frontier states, a
    /// next-required body is always either scheduled for recovery this tick
    /// or carries an explicit `NoProgressReason` — never both absent.
    #[test]
    fn plan_never_leaves_a_required_body_unaccounted(
        applied_ahead in proptest::bool::ANY,
        next_required in proptest::option::of(0_u32..16),
        apply_halted in proptest::bool::ANY,
        body_case in 0_u8..3,
        in_flight_live in proptest::bool::ANY,
        peers in proptest::collection::vec(
            (0_i32..32, proptest::bool::ANY),
            0..5usize,
        ),
        pending_live in proptest::bool::ANY,
    ) {
        let applied = snap(1, 8, 0x01);
        let chain_tip = if applied_ahead {
            Arc::clone(&applied)
        } else {
            snap(2, 12, 0x02)
        };
        // `evidenced` peers carry demonstrated tips that resolve off the
        // active chain, so `capability()` yields `None` — crossing the
        // no-capable-peer branch, not just empty-vs-nonempty peers.
        let usable_peers = peers
            .iter()
            .enumerate()
            .map(|(idx, (height, evidenced))| {
                let mut peer = usable(
                    u16::try_from(9100 + idx).unwrap_or(9100),
                    *height,
                    None,
                );
                if *evidenced {
                    peer.demonstrated_tips = vec![hash(0x77)];
                }
                peer
            })
            .collect::<Vec<_>>();
        // InFlight crosses both directions of the identity-exact owner
        // check: a live owner counts as progress; an owner absent from the
        // usable set is unowned work and must be re-requested.
        let body_state = next_required.map(|_height| match body_case {
            0 => BodyState::Unowned,
            1 => BodyState::Staged,
            _ => {
                if in_flight_live {
                    usable_peers.first().map_or(BodyState::Unowned, |peer| {
                        BodyState::InFlight(peer.source)
                    })
                } else {
                    BodyState::InFlight(PeerSource::for_test(addr_of(9999)))
                }
            }
        });
        let owner = usable_peers.first().map(|peer| peer.source);
        let header_request = if let (true, Some(source)) = (pending_live, owner) {
            Some(super::super::PendingHeaderRequest {
                source,
                locator_tip_hash: hash(0x01),
                target_height: 9,
                requested_at: Instant::now(),
                answered: false,
            })
        } else {
            None
        };
        let frontier = SyncFrontier {
            chain: ChainFrontier {
                applied_tip: Some(applied),
                chain_tip: Some(chain_tip),
                next_required: next_required.map(|height| RequiredBody {
                    height,
                    hash: hash(0x03),
                }),
                apply_halted,
            },
            body_state,
            header_request,
            header_request_live: header_request.is_some(),
            usable_peers,
        };
        let plan = frontier.plan();
        if frontier.chain.next_required.is_some() {
            proptest::prop_assert!(
                plan.schedule_bodies || plan.no_progress.is_some(),
                "required body must schedule recovery or name the reason: \
                 {plan:?}"
            );
        }
        // A live in-flight owner counts as progress: no incapability
        // verdict and recovery keeps scheduling while its work is pending.
        if let Some(BodyState::InFlight(owner)) = frontier.body_state
            && !frontier.chain.apply_halted
            && frontier
                .usable_peers
                .iter()
                .any(|peer| peer.source == owner)
        {
            proptest::prop_assert!(plan.schedule_bodies, "live owner is progress: {plan:?}");
            proptest::prop_assert_eq!(plan.no_progress, None);
        }
        // An owner absent from the usable set is unowned work: when no
        // capable peer exists the plan must carry NoCapablePeer rather than
        // silently relying on the dead connection.
        if let Some(BodyState::InFlight(owner)) = frontier.body_state
            && !frontier.usable_peers.is_empty()
            && !frontier.usable_peers.iter().any(|peer| peer.source == owner)
            && !frontier.chain.apply_halted
            && !frontier
                .usable_peers
                .iter()
                .any(|peer| peer.capability().is_some())
        {
            proptest::prop_assert_eq!(
                plan.no_progress,
                Some(NoProgressReason::NoCapablePeer)
            );
        }
        // NoUsablePeers is reserved for an actually-empty usable set: the
        // verdict must never fire while peers exist, and every empty-peer
        // frontier with a required body must carry it (rather than a
        // misattributed capability verdict).
        if plan.no_progress == Some(NoProgressReason::NoUsablePeers) {
            proptest::prop_assert!(frontier.usable_peers.is_empty());
        }
        if frontier.usable_peers.is_empty()
            && frontier.chain.next_required.is_some()
            && !frontier.chain.apply_halted
        {
            proptest::prop_assert_eq!(
                plan.no_progress,
                Some(NoProgressReason::NoUsablePeers)
            );
        }
    }
}

/// #1129's residual hole, closed: a replacement connection that registers
/// between the predecessor's conviction and the release sweep must neither
/// be blamed for the predecessor's stall nor lose the released work.
#[test]
fn convicted_connection_cannot_pass_its_stall_to_a_replacement()
-> Result<(), Box<dyn std::error::Error>> {
    let (sync, peers, block_tree, applied_tip, expected) = sync_with_header_chain(4)?;
    // One received block must arm the stall predicate.
    install_budget(
        &sync,
        super::super::SyncBudget {
            max_received_blocks: 2,
            ..super::super::default_sync_budget(Network::Regtest)
        },
    );
    let staller = test_addr(9810, 0)?;
    let (tx, rx) = unbounded::<Message>();
    let conn1 = PeerLease::new(tx);
    peers.register(staller, conn1.clone());
    peers.publish_info(staller, &conn1, synthetic_peer(staller, 200));

    sync.tick();
    assert_applied_genesis(&applied_tip, &block_tree)?;
    let Message::GetData(inventory) = rx.try_recv()? else {
        return Err(std::io::Error::other("expected the window getdata").into());
    };
    assert!(witness_block_inventory(inventory)?.contains(&expected[0]));

    // Stage a successor so the stall predicate arms: the front pending
    // owner plus received backlog is the wedge the stall machine watches.
    let tail = Hash256::from_le_bytes(expected[3].as_bytes());
    let now = Instant::now();
    {
        let mut scheduler = sync.scheduler.lock();
        let block = super::mined_block_with_prev_hash(
            BlockHash(Hash256::from_le_bytes(expected[2].as_bytes())),
            4,
            vec![super::transaction(0xEE)],
        );
        let serialized = bytes::Bytes::from(consensus_bytes(&block));
        scheduler.window.seed_front_cadence_for_test(50, now);
        scheduler.stager.insert(
            tail,
            None,
            block,
            serialized,
            Some(conn1.source(staller)),
            now,
        );
        scheduler
            .window
            .mark_received_from(tail, 80, Some(conn1.source(staller)), now);
    }

    // The stall matures on conn1; its replacement registers before the
    // disconnect lands — the ordering that defeated addr-keyed blame.
    let next_apply = sync
        .observe_chain_frontier()
        .next_required
        .ok_or_else(|| std::io::Error::other("missing next required"))?
        .height;
    {
        let mut scheduler = sync.scheduler.lock();
        let tree = sync.chain.block_tree().read();
        let state = &mut *scheduler;
        stall_blame(&mut state.window, &state.stager, &tree, next_apply, now);
    }
    let owner = {
        let mut scheduler = sync.scheduler.lock();
        let tree = sync.chain.block_tree().read();
        let state = &mut *scheduler;
        stall_blame(
            &mut state.window,
            &state.stager,
            &tree,
            next_apply,
            now + super::super::BLOCK_STALLING_TIMEOUT,
        )
    };
    let (tx2, rx2) = unbounded::<Message>();
    let conn2 = PeerLease::new(tx2);
    peers.register(staller, conn2.clone());
    peers.publish_info(staller, &conn2, synthetic_peer(staller, 200));

    // Conviction is exact: the convicted source is conn1, already replaced,
    // so the disconnect lands on nobody — and specifically not on conn2.
    let owner = owner.ok_or_else(|| std::io::Error::other("missing stall owner"))?;
    assert!(
        !peers.disconnect_source(owner),
        "convicting a replaced connection must not disconnect its successor"
    );
    let conn2_source = conn2.source(staller);
    assert!(peers.is_current(conn2_source));
    assert!(!conn2.is_cancelled());
    sync.reconcile_peer_sessions();

    // The released front goes to the only live peer: conn2. A cooldown or
    // inherited conviction would hold it out of the window front.
    sync.tick();
    let Message::GetData(reissued) = rx2.try_recv()? else {
        return Err(std::io::Error::other(
            "the replacement must inherit the released frontier work",
        )
        .into());
    };
    assert!(
        witness_block_inventory(reissued)?.contains(&expected[0]),
        "conn1's released front must be re-requested from conn2"
    );
    Ok(())
}

/// The window-level half of the same pin: once the replacement owns the
/// re-issued frontier, a release sweep for the dead predecessor's identity
/// leaves it untouched, while a sweep naming the replacement releases it.
#[test]
fn release_sweep_is_connection_exact_at_the_same_address() -> Result<(), Box<dyn std::error::Error>>
{
    let (sync, peers, block_tree, applied_tip, expected) = sync_with_header_chain(4)?;
    let addr = test_addr(9820, 0)?;
    let rx = connect_peer(&peers, synthetic_peer(addr, 200));
    sync.tick();
    assert_applied_genesis(&applied_tip, &block_tree)?;
    let Message::GetData(inventory) = rx.try_recv()? else {
        return Err(std::io::Error::other("expected the window getdata").into());
    };
    assert!(witness_block_inventory(inventory)?.contains(&expected[0]));
    let owner = current_source(&peers, addr);
    let front = Hash256::from_le_bytes(expected[0].as_bytes());
    assert_eq!(
        sync.scheduler.lock().window.pending_owner(&front),
        Some(owner)
    );

    // A sweep whose live set lists only this connection keeps its work;
    // one that does not releases it, even though the addr is unchanged.
    sync.scheduler
        .lock()
        .window
        .retain_owned_by(|source| *source == owner);
    assert_eq!(
        sync.scheduler.lock().window.pending_owner(&front),
        Some(owner),
        "the live connection's pending must survive a release sweep"
    );
    sync.scheduler.lock().window.retain_owned_by(|_| false);
    assert_eq!(
        sync.scheduler.lock().window.pending_owner(&front),
        None,
        "a sweep missing the connection must release its pending"
    );
    Ok(())
}

/// The header-request deadline is evaluated on the injected clock, never on
/// wall time: one nanosecond short of `HEADER_REQUEST_TIMEOUT` keeps the gate
/// live, the deadline itself retires it and penalises its owner.
#[test]
fn header_request_deadline_is_evaluated_on_the_injected_clock()
-> Result<(), Box<dyn std::error::Error>> {
    let HeaderSyncFixture {
        sync,
        inbound_headers_tx: _inbound_headers_tx,
        peers,
        ..
    } = header_sync_with_genesis()?;
    let addr = test_addr(9160, 0)?;
    let rx = connect_peer(&peers, synthetic_peer(addr, 8));
    connect_peer(&peers, synthetic_peer(test_addr(9160, 1)?, 8));
    let t0 = Instant::now();
    let source = current_source(&peers, addr);

    sync.tick_at(t0);
    assert!(
        rx.try_iter()
            .any(|message| matches!(message, Message::GetHeaders(_))),
        "the first tick must put the request on the wire"
    );

    // A tick well inside the deadline: nothing may be retired or penalised.
    let well_inside = t0 + super::super::HEADER_REQUEST_TIMEOUT / 2;
    sync.tick_at(well_inside);
    let scheduler = sync.scheduler.lock();
    assert!(
        scheduler
            .header_request
            .is_some_and(|request| request.source == source),
        "a request still inside its deadline must stay as the gate"
    );
    assert!(
        scheduler.header_penalties.is_empty(),
        "a request still inside its deadline must not be penalised"
    );
    drop(scheduler);

    // The deadline itself retires the request and charges its owner.
    let at_deadline = t0 + super::super::HEADER_REQUEST_TIMEOUT;
    sync.tick_at(at_deadline);
    let scheduler = sync.scheduler.lock();
    assert!(
        !scheduler
            .header_request
            .is_some_and(|request| request.source == source),
        "the deadline retires the timed-out connection's gate"
    );
    assert_eq!(
        scheduler.header_penalties.get(&source).copied(),
        Some(1),
        "the timed-out connection carries exactly its own strike"
    );
    Ok(())
}
