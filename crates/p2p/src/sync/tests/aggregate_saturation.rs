//! The node's aggregate outbound budget is backpressure for block sync, never
//! a reason to disconnect a healthy peer: a refused `getheaders` or `getdata`
//! queues and marks nothing, and the next tick rebuilds the request.

use super::*;
use crate::connection::SharedOutboundBudget;
use crate::test_support::hog;

/// A registered connection whose queue also charges `aggregate`.
fn connect_on(
    peers: &Arc<PeerTable>,
    aggregate: &Arc<SharedOutboundBudget>,
    info: PeerInfo,
) -> (PeerLease, crate::test_support::MessageReceiver) {
    let (queue, receiver) = crate::test_support::message_channel();
    let lease = PeerLease::new(queue).with_shared_budget(aggregate);
    peers.register(
        info.endpoint.expect("identified peer endpoint"),
        lease.clone(),
    );
    peers.publish_info(
        info.endpoint.expect("identified peer endpoint"),
        &lease,
        info,
    );
    (lease, receiver)
}

#[test]
fn getheaders_saturated_no_disconnect() -> TestResult {
    let mut tree = BlockTree::new();
    let genesis = genesis_header();
    tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
    let harness = SyncHarness::with_ibd(tree, crate::sync::syncing_ibd_latch());
    let (sync, peers) = (harness.sync, harness.peers);
    let aggregate = Arc::new(SharedOutboundBudget::with_limits(512, 0));
    let hold = hog(&aggregate, 512);
    let addr = test_addr(9_700, 0)?;
    let (lease, rx) = connect_on(&peers, &aggregate, synthetic_peer(addr, 10));
    let source = lease.source_ip(addr);
    let locator = || vec![Hash256::from(genesis.compute_hash())];

    assert_eq!(
        sync.send_getheaders(source, 0, 10, locator()),
        super::super::GetheadersOutcome::Failed,
        "the refused request fails this tick only"
    );
    assert!(
        !lease.is_cancelled() && peers.is_current(source),
        "a full aggregate is not a dead connection"
    );
    assert!(rx.is_empty(), "nothing was queued");
    assert!(
        sync.scheduler
            .lock()
            .headers_sync
            .get(&source)
            .and_then(|owned| owned.request)
            .is_none(),
        "nothing was stamped, so the next tick rebuilds the request"
    );

    drop(hold);
    assert_eq!(
        sync.send_getheaders(source, 0, 10, locator()),
        super::super::GetheadersOutcome::Sent
    );
    assert!(matches!(rx.try_recv()?, Message::GetHeaders(_)));
    assert!(
        sync.scheduler
            .lock()
            .headers_sync
            .get(&source)
            .is_some_and(|owned| owned.request.is_some()),
        "the sent request is stamped under the connection's identity"
    );
    Ok(())
}

#[test]
fn block_getdata_saturated_marks_nothing_and_is_replanned() -> TestResult {
    let (sync, peers, _block_tree, _applied_tip, expected) =
        sync_with_header_chain_and_ibd(4, synced_ibd_latch())?;
    let aggregate = Arc::new(SharedOutboundBudget::with_limits(4_096, 0));
    let hold = hog(&aggregate, 4_096);
    let addr = test_addr(9_701, 0)?;
    let (lease, rx) = connect_on(&peers, &aggregate, synthetic_peer(addr, 286));

    sync.tick();

    assert_no_getdata(&rx)?;
    assert!(
        !lease.is_cancelled() && peers.is_connected(crate::PeerEndpoint::Ip(addr)),
        "a full aggregate does not disconnect the peer being asked"
    );
    assert_eq!(
        sync.scheduler.lock().window.pending_len(),
        0,
        "a refused request marks no block in flight"
    );

    drop(hold);
    sync.tick();

    assert_eq!(
        witness_block_inventory(next_getdata(&rx)?)?,
        expected,
        "the next tick plans the same request again"
    );
    Ok(())
}
