//! Header drain budgets must leave time for block application and scheduling.

use super::super::headers::{MAX_HEADER_BATCHES_PER_TICK, MAX_HEADERS_PER_TICK};
use super::*;

#[test]
fn header_backlog_yields_to_block_apply_and_request_scheduling() -> TestResult {
    let (tree, blocks) = mined_chain(2, 0)?;
    let SyncHarness {
        sync,
        peers,
        applied_tip,
        inbound_headers_tx,
        inbound_blocks_tx,
        ..
    } = SyncHarness::new(tree);
    let peer = test_addr(9790, 0)?;
    let rx = connect_peer(&peers, synthetic_peer(peer, 2));
    let old_peer = test_addr(9791, 0)?;
    let _old_rx = connect_peer(&peers, synthetic_peer(old_peer, 2));
    let stale = current_source(&peers, old_peer);
    assert!(peers.disconnect_source(stale));

    // Both empty wire responses and stale-source batches must cost a slot.
    for n in 0..2 * MAX_HEADER_BATCHES_PER_TICK {
        inbound_headers_tx.send(InboundHeaders {
            headers: Vec::new(),
            source: n.is_multiple_of(2).then_some(stale),
            wire_response: true,
        })?;
    }
    inbound_blocks_tx.send(crate::InboundBlock::from_local(blocks[0].clone()))?;
    let started = Instant::now();
    sync.tick();
    eprintln!(
        "tick with empty/stale header backlog: {:?}",
        started.elapsed()
    );
    assert_eq!(sync.inbound_headers_rx.len(), MAX_HEADER_BATCHES_PER_TICK);
    assert_eq!(applied_tip.load_full().ok_or("no applied block")?.height, 1);
    assert!(
        next_getdata(&rx)?.iter().any(|item| {
            matches!(item, Inventory::WitnessBlock(hash) if Hash256::from_le_bytes(hash.as_byte_array()) == Hash256::from(blocks[1].block_hash()))
        }),
        "the same tick must schedule the next body despite queued headers"
    );
    sync.tick();
    assert!(sync.inbound_headers_rx.is_empty());
    Ok(())
}

#[test]
fn header_work_budget_keeps_whole_batches_in_order() -> TestResult {
    let page = crate::wire::MAX_HEADERS_MESSAGE_COUNT;
    // Exercise both the exact boundary and one final whole-page overshoot.
    for lengths in [vec![page, page, 1], vec![page - 1, page, page, 0]] {
        let mut tree = BlockTree::new();
        let genesis = genesis_header();
        tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
        let SyncHarness {
            sync,
            inbound_headers_tx,
            ..
        } = SyncHarness::new(tree);
        for len in &lengths {
            inbound_headers_tx.send(InboundHeaders {
                headers: vec![genesis; *len],
                source: None,
                wire_response: true,
            })?;
        }
        sync.drain_inbound_headers();
        assert_eq!(sync.inbound_headers_rx.len(), 1);
        let last = sync.inbound_headers_rx.try_recv()?;
        assert_eq!(last.headers.len(), *lengths.last().ok_or("empty lengths")?);
        let processed: usize = lengths[..lengths.len() - 1].iter().sum();
        assert!((MAX_HEADERS_PER_TICK..MAX_HEADERS_PER_TICK + page).contains(&processed));
    }
    Ok(())
}
