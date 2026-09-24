//! Block-download service eligibility: the initial-block-download rule and the
//! retained-window rule for pruned peers.
//!
//! Bitcoin Core never asks a pruned peer for blocks it may have deleted.
//! During initial block download only a `NODE_NETWORK` peer serves bodies
//! (`net_processing.cpp:6521`); afterwards a peer without `NODE_NETWORK`
//! serves only the last `NODE_NETWORK_LIMITED_MIN_BLOCKS` — 288
//! (`net_processing.cpp:159`, window applied at `:1637`) — of its own chain.
//! Both the selection path and the shared predicate are pinned here, because a
//! fix that lands on one path alone leaves the other requesting undeliverable
//! blocks.

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
    }
}

/// Everything the connection was sent so far.
fn sent_messages(rx: &crossbeam_channel::Receiver<Message>) -> Vec<Message> {
    rx.try_iter().collect()
}

/// During initial block download a pruned peer may not serve bodies at any
/// height: the blocks the node is asking for are exactly the ones a pruned peer
/// has discarded.
#[test]
fn predicate_excludes_limited_peer_during_initial_block_download()
-> Result<(), Box<dyn std::error::Error>> {
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

/// After the latch is off, a peer without `NODE_NETWORK` serves the last 288
/// blocks of its own chain and nothing older: 287 blocks behind its tip is
/// inside the window, 288 behind is not, and a peer that has not demonstrated
/// the requested height is ineligible.
#[test]
fn predicate_limits_pruned_peer_to_the_retained_window() -> Result<(), Box<dyn std::error::Error>> {
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

/// A `NODE_NETWORK` peer is unaffected by the phase or the window: the retained
/// rule is about pruned storage, not about chain length.
#[test]
fn predicate_keeps_full_service_peer_at_any_height() -> Result<(), Box<dyn std::error::Error>> {
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

/// The selection path agrees with the predicate: while the node is still in
/// initial block download, a connected pruned peer receives header requests
/// only — never a `getdata`.
#[test]
fn tick_asks_no_bodies_from_limited_peer_during_initial_block_download()
-> Result<(), Box<dyn std::error::Error>> {
    let (sync, peers, _tree, _applied, _expected) =
        sync_with_header_chain_and_ibd(4, crate::sync::syncing_ibd_latch())?;
    let rx = connect_peer(&peers, limited_peer(test_addr(9603, 0)?, 300));

    sync.tick();
    sync.tick();

    // One drain, then both clauses: no body request, headers still open.
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

/// After initial block download the same peer serves the near-tip range, and
/// the selection is the deep single-peer batch, so the body request proves the
/// predicate ran inside the tick and not only in isolation.
#[test]
fn tick_asks_bodies_from_limited_peer_inside_retained_window()
-> Result<(), Box<dyn std::error::Error>> {
    let (sync, peers, block_tree, applied_tip, expected) =
        sync_with_header_chain_and_ibd(4, synced_ibd_latch())?;
    let rx = connect_peer(&peers, limited_peer(test_addr(9604, 0)?, 288));

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

/// One block older and the peer is outside its retained window: the node leaves
/// the bodies unrequested rather than asking a peer that cannot deliver them.
#[test]
fn tick_asks_no_bodies_from_limited_peer_beyond_retained_window()
-> Result<(), Box<dyn std::error::Error>> {
    let (sync, peers, block_tree, applied_tip, _expected) =
        sync_with_header_chain_and_ibd(4, synced_ibd_latch())?;
    let rx = connect_peer(&peers, limited_peer(test_addr(9605, 0)?, 289));

    sync.tick();
    assert_applied_genesis(&applied_tip, &block_tree)?;

    assert_no_getdata(&rx)?;
    Ok(())
}

/// The fan-out set must not include a pruned peer while the node is still
/// syncing: were it counted, the window would stripe the old range across a
/// peer that can only serve its last 288 blocks.
#[test]
fn limited_peer_is_not_counted_toward_fanout_during_initial_block_download()
-> Result<(), Box<dyn std::error::Error>> {
    let (sync, peers, _tree, _applied, _expected) = sync_with_header_chain_and_ibd(
        u32::try_from(PENDING_BUDGET)?,
        crate::sync::syncing_ibd_latch(),
    )?;
    // The highest chain in the set: the old witness-only rule would have made
    // this the first pick for the deep batch.
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
