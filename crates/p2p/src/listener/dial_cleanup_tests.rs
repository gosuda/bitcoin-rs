#![expect(clippy::expect_used, reason = "fixture setup must fail loudly")]

use std::net::TcpListener;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use super::{ConnectionOrigin, FailureAccounting, TransportChoice, dial, test_shared};
use crate::PeerRole;

#[test]
fn a_failed_cancel_guard_removes_the_registered_outbound_lease() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
    let address = listener.local_addr().expect("address");
    let shared = Arc::new(test_shared(
        Arc::new(crate::PeerTable::new()),
        crossbeam_channel::unbounded().0,
        crossbeam_channel::unbounded().0,
    ));
    crate::counters::CANCEL_CLONE_FAIL.store(true, Ordering::Relaxed);

    let outcome = dial(
        address.into(),
        &shared,
        PeerRole::FullRelay,
        ConnectionOrigin::Manual,
        FailureAccounting::Ignore,
        TransportChoice::ForceV1,
    );

    assert!(
        matches!(outcome, Err(crate::PeerError::Io(_))),
        "the injected cancel-guard failure must fail the dial: {outcome:?}"
    );
    assert!(
        !shared.peer_table.is_connected(address),
        "the dial must not leave the registered lease in the peer table"
    );
}
