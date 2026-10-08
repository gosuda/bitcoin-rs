//! Block-download service eligibility: the initial-block-download rule and the
//! retained-window rule for pruned peers.

use std::sync::Arc;

use bitcoin::p2p::ServiceFlags;

use super::*;
use crate::download_window::{
    BlockDownloadPolicy, MIN_PEERS_FOR_FANOUT, PENDING_BUDGET, statically_fanout_eligible,
};

/// A pruned peer: witness relay plus `NODE_NETWORK_LIMITED`, no `NODE_NETWORK`.
fn limited_peer(addr: SocketAddr, height: i32) -> PeerInfo {
    PeerInfo {
        services: ServiceFlags::WITNESS.to_u64() | ServiceFlags::NETWORK_LIMITED.to_u64(),
        ..synthetic_peer(addr, height)
    }
}

/// A full-history peer: `NODE_NETWORK | NODE_WITNESS`, the [`synthetic_peer`]
/// default.
fn full_peer(addr: SocketAddr, height: i32) -> PeerInfo {
    synthetic_peer(addr, height)
}

fn policy(ibd: Arc<InitialBlockDownload>, requested_height: u32) -> BlockDownloadPolicy {
    BlockDownloadPolicy {
        ibd,
        requested_height,
        network: Network::Regtest,
    }
}

/// Everything the connection was sent so far.
fn sent_messages(rx: &crossbeam_channel::Receiver<Message>) -> Vec<Message> {
    rx.try_iter().collect()
}

#[test]
fn predicate_excludes_limited_peer_during_initial_block_download() -> TestResult {
    let addr = test_addr(9600, 0)?;
    let syncing = crate::sync::syncing_ibd_latch();
    assert!(
        !statically_fanout_eligible(&limited_peer(addr, 300), &policy(syncing.clone(), 1)),
        "a pruned peer must never serve bodies while the node is still syncing"
    );
    assert!(
        statically_fanout_eligible(&full_peer(addr, 300), &policy(syncing, 1)),
        "a full-history peer serves bodies during initial block download"
    );
    Ok(())
}

#[test]
fn predicate_limits_pruned_peer_to_the_retained_window() -> TestResult {
    let addr = test_addr(9601, 0)?;
    for (height, requested, accepted) in [
        (288_i32, 1_u32, true),
        (289, 1, false),
        (300, 13, true),
        (288, 288, true),
        (287, 288, false),
        (300, 1, false),
    ] {
        assert_eq!(
            statically_fanout_eligible(
                &limited_peer(addr, height),
                &policy(synced_ibd_latch(), requested),
            ),
            accepted,
            "pruned peer at {height} asked for height {requested}"
        );
    }
    Ok(())
}

#[test]
fn predicate_refuses_witness_only_peer_inside_the_window() -> TestResult {
    let addr = test_addr(9603, 0)?;
    let witness_only = PeerInfo {
        services: ServiceFlags::WITNESS.to_u64(),
        ..synthetic_peer(addr, 300)
    };
    for requested in [1_u32, 13, 288] {
        assert!(
            !statically_fanout_eligible(&witness_only, &policy(synced_ibd_latch(), requested)),
            "a WITNESS-only peer must not be sent a getdata for height {requested}"
        );
    }
    Ok(())
}

#[test]
fn predicate_keeps_full_service_peer_at_any_height() -> TestResult {
    let addr = test_addr(9602, 0)?;
    for ibd in [crate::sync::syncing_ibd_latch(), synced_ibd_latch()] {
        assert!(statically_fanout_eligible(
            &full_peer(addr, 300),
            &policy(Arc::clone(&ibd), 1),
        ));
        assert!(statically_fanout_eligible(
            &full_peer(addr, 300),
            &policy(ibd, 300),
        ));
    }
    Ok(())
}

#[test]
fn tick_asks_no_bodies_from_limited_peer_during_initial_block_download() -> TestResult {
    let (sync, peers, _tree, _applied, _expected) =
        sync_with_header_chain_and_ibd(4, crate::sync::syncing_ibd_latch())?;
    let rx = connect_peer(&peers, limited_peer(test_addr(9603, 0)?, 300));

    sync.tick();
    sync.tick();

    let messages = sent_messages(&rx);
    assert!(
        !messages
            .iter()
            .any(|message| matches!(message, Message::GetData(_))),
        "a pruned peer must not be asked for bodies while the node is still syncing"
    );
    assert!(
        messages
            .iter()
            .any(|message| matches!(message, Message::GetHeaders(_))),
        "header requests stay open to a pruned peer, got {messages:?}"
    );
    Ok(())
}

#[test]
fn tick_asks_bodies_from_limited_peer_inside_retained_window() -> TestResult {
    let (sync, peers, block_tree, applied_tip, expected) =
        sync_with_header_chain_and_ibd(4, synced_ibd_latch())?;
    let rx = connect_peer(&peers, limited_peer(test_addr(9604, 0)?, 286));

    sync.tick();
    assert_applied_genesis(&applied_tip, &block_tree)?;

    let inventory = next_getdata(&rx)?;
    assert_eq!(
        witness_block_inventory(inventory)?,
        expected,
        "the pruned peer keeps the last 288 blocks, so the near-tip range is its own"
    );
    Ok(())
}

#[test]
fn tick_asks_no_bodies_from_limited_peer_beyond_retained_window() -> TestResult {
    let (sync, peers, block_tree, applied_tip, _expected) =
        sync_with_header_chain_and_ibd(4, synced_ibd_latch())?;
    let rx = connect_peer(&peers, limited_peer(test_addr(9605, 0)?, 287));

    sync.tick();
    assert_applied_genesis(&applied_tip, &block_tree)?;

    assert_no_getdata(&rx)?;
    Ok(())
}

#[test]
fn limited_peer_is_not_counted_toward_fanout_during_initial_block_download() -> TestResult {
    let (sync, peers, _tree, _applied, _expected) = sync_with_header_chain_and_ibd(
        u32::try_from(PENDING_BUDGET)?,
        crate::sync::syncing_ibd_latch(),
    )?;
    let limited_rx = connect_peer(&peers, limited_peer(test_addr(9606, 0)?, 400));
    let mut rxs = Vec::new();
    for idx in 0..MIN_PEERS_FOR_FANOUT {
        let addr = test_addr(9607, idx)?;
        rxs.push(connect_peer(
            &peers,
            full_peer(addr, 300 - i32::try_from(idx)?),
        ));
    }

    sync.tick();
    sync.tick();

    assert_no_getdata(&limited_rx)?;
    for rx in &rxs {
        assert!(
            next_getdata(rx).is_ok(),
            "every full-service peer must be asked for bodies"
        );
    }
    Ok(())
}
