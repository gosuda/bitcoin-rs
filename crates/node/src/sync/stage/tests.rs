use bitcoin_rs_p2p::default_sync_budget;

use bitcoin_rs_primitives::{
    Amount, Block, Hash256, LockTime, Network, OutPoint, Script, Sequence, Tx, TxIn, TxOut,
    Witness, consensus_bytes,
};

use std::time::{Duration, Instant};

use super::{BlockStager, block_size};

#[test]
fn block_size_matches_consensus_serialized_len() {
    let block = Network::Regtest.genesis_block();

    assert_eq!(block_size(&block), consensus_bytes(&block).len());
}

#[test]
fn drain_expected_prefix_stops_at_first_missing_hash() {
    let block = Network::Regtest.genesis_block();
    let serialized = bytes::Bytes::from(consensus_bytes(&block));
    let block_bytes = block_size(&block);
    let mut stager = BlockStager::new(default_sync_budget());
    let now = std::time::Instant::now();
    let first = Hash256::from_le_bytes(&[0x01; 32]);
    let missing = Hash256::from_le_bytes(&[0x02; 32]);
    let third = Hash256::from_le_bytes(&[0x03; 32]);
    let fourth = Hash256::from_le_bytes(&[0x04; 32]);

    stager.insert(first, None, block.clone(), serialized.clone(), now);
    stager.insert(third, None, block.clone(), serialized.clone(), now);
    stager.insert(fourth, None, block, serialized, now);

    let drained = stager.drain_expected_prefix(&[first, missing, third, fourth]);

    assert_eq!(drained.len(), 1);
    assert_eq!(drained[0].hash, first);
    assert_eq!(stager.received_len(), 2);
    assert_eq!(stager.received_bytes(), block_bytes.saturating_mul(2));
    assert!(stager.contains(&third));
    assert!(stager.contains(&fourth));
}

#[test]
fn staged_body_lookup_preserves_the_entry() {
    let block = Network::Regtest.genesis_block();
    let serialized = bytes::Bytes::from(consensus_bytes(&block));
    let hash = Hash256::from_le_bytes(&[0x05; 32]);
    let mut stager = BlockStager::new(default_sync_budget());
    stager.insert(
        hash,
        None,
        block.clone(),
        serialized.clone(),
        Instant::now(),
    );

    let Some((loaded, loaded_serialized)) = stager.staged_body(hash) else {
        panic!("inserted body must remain readable");
    };

    assert_eq!(loaded, block);
    assert_eq!(loaded_serialized, serialized);
    assert_eq!(stager.received_len(), 1);
    assert!(stager.contains(&hash));
}

#[test]
fn restore_many_restores_tail_byte_accounting() {
    let block = Network::Regtest.genesis_block();
    let serialized = bytes::Bytes::from(consensus_bytes(&block));
    let block_bytes = block_size(&block);
    let mut stager = BlockStager::new(default_sync_budget());
    let now = std::time::Instant::now();
    let first = Hash256::from_le_bytes(&[0x11; 32]);
    let second = Hash256::from_le_bytes(&[0x22; 32]);
    let third = Hash256::from_le_bytes(&[0x33; 32]);

    stager.insert(first, None, block.clone(), serialized.clone(), now);
    stager.insert(second, None, block.clone(), serialized.clone(), now);
    stager.insert(third, None, block, serialized, now);
    let mut drained = stager.drain_expected_prefix(&[first, second, third]);
    assert_eq!(stager.received_order_len(), 0);
    assert_eq!(stager.next_received_deadline, None);
    let restored_tail = drained.split_off(1);

    stager.restore_many(restored_tail);

    assert_eq!(stager.received_len(), 2);
    assert_eq!(stager.received_order_len(), 2);
    assert_eq!(stager.received_bytes(), block_bytes.saturating_mul(2));
    assert!(!stager.contains(&first));
    assert!(stager.contains(&second));
    assert!(stager.contains(&third));
}

#[test]
fn ready_received_len_requires_next_expected_hash_when_provided() {
    let block = Network::Regtest.genesis_block();
    let serialized = bytes::Bytes::from(consensus_bytes(&block));
    let mut stager = BlockStager::new(default_sync_budget());
    let now = std::time::Instant::now();
    let staged = Hash256::from_le_bytes(&[0x31; 32]);
    let missing = Hash256::from_le_bytes(&[0x32; 32]);

    assert_eq!(stager.ready_received_len(None), None);

    stager.insert(staged, None, block, serialized, now);

    assert_eq!(stager.ready_received_len(None), Some(1));
    assert_eq!(stager.ready_received_len(Some(staged)), Some(1));
    assert_eq!(stager.ready_received_len(Some(missing)), None);
}

#[test]
fn prune_expired_recomputes_deadline_after_dropping_oldest() {
    let block = Network::Regtest.genesis_block();
    let serialized = bytes::Bytes::from(consensus_bytes(&block));
    let mut budget = default_sync_budget();
    budget.received_timeout = Duration::from_secs(10);
    let mut stager = BlockStager::new(budget);
    let now = Instant::now();
    let old_received_at = now
        .checked_sub(Duration::from_secs(11))
        .unwrap_or_else(|| panic!("test instant underflow"));
    let fresh_received_at = now
        .checked_sub(Duration::from_secs(1))
        .unwrap_or_else(|| panic!("test instant underflow"));
    let old = Hash256::from_le_bytes(&[0x41; 32]);
    let fresh = Hash256::from_le_bytes(&[0x42; 32]);

    stager.insert(
        old,
        None,
        block.clone(),
        serialized.clone(),
        old_received_at,
    );
    stager.insert(fresh, None, block, serialized, fresh_received_at);

    let first_drop = stager.prune_expired(now);

    assert_eq!(first_drop.len(), 1);
    assert_eq!(first_drop[0].hash, old);
    assert_eq!(stager.received_len(), 1);
    assert!(stager.contains(&fresh));

    let second_drop = stager.prune_expired(now + Duration::from_secs(1));

    assert!(second_drop.is_empty());
    assert!(stager.contains(&fresh));

    let final_drop = stager.prune_expired(now + Duration::from_secs(10));

    assert_eq!(final_drop.len(), 1);
    assert_eq!(final_drop[0].hash, fresh);
    assert_eq!(stager.received_len(), 0);
}

#[test]
fn duplicate_insert_keeps_original_staged_deadline() {
    let block = Network::Regtest.genesis_block();
    let serialized = bytes::Bytes::from(consensus_bytes(&block));
    let block_bytes = block_size(&block);
    let mut budget = default_sync_budget();
    budget.received_timeout = Duration::from_secs(10);
    let mut stager = BlockStager::new(budget);
    let now = Instant::now();
    let hash = Hash256::from_le_bytes(&[0x43; 32]);

    stager.insert(hash, None, block.clone(), serialized.clone(), now);
    stager.insert(hash, None, block, serialized, now + Duration::from_secs(5));

    assert_eq!(stager.received_len(), 1);
    assert_eq!(stager.received_bytes(), block_bytes);

    let dropped = stager.prune_expired(now + Duration::from_secs(10));

    assert_eq!(dropped.len(), 1);
    assert_eq!(dropped[0].hash, hash);
    assert_eq!(stager.received_len(), 0);
    assert_eq!(stager.received_bytes(), 0);
}

#[test]
fn insert_eviction_drops_oldest_unprotected_until_budget_fits() {
    let block = Network::Regtest.genesis_block();
    let serialized = bytes::Bytes::from(consensus_bytes(&block));
    let block_bytes = block_size(&block);
    let mut stager = BlockStager::new(default_sync_budget());
    let now = Instant::now();
    let protected = Hash256::from_le_bytes(&[0x51; 32]);
    let first = Hash256::from_le_bytes(&[0x52; 32]);
    let second = Hash256::from_le_bytes(&[0x53; 32]);
    let third = Hash256::from_le_bytes(&[0x54; 32]);
    let incoming = Hash256::from_le_bytes(&[0x55; 32]);

    stager.insert(protected, None, block.clone(), serialized.clone(), now);
    stager.insert(
        first,
        None,
        block.clone(),
        serialized.clone(),
        now + Duration::from_secs(1),
    );
    stager.insert(
        second,
        None,
        block.clone(),
        serialized.clone(),
        now + Duration::from_secs(2),
    );
    stager.insert(
        third,
        None,
        block.clone(),
        serialized.clone(),
        now + Duration::from_secs(3),
    );
    stager.budget.max_received_blocks = 2;

    let dropped = match stager.insert(
        incoming,
        Some(protected),
        block,
        serialized,
        now + Duration::from_secs(4),
    ) {
        super::StagedBlock::AlreadyStaged => {
            panic!("incoming block should not already be staged")
        }
        super::StagedBlock::Memory { dropped, .. } => dropped,
        super::StagedBlock::DroppedForRetry { .. } => {
            panic!("incoming block should fit after evicting staged blocks")
        }
    };

    assert_eq!(dropped.len(), 3);
    assert_eq!(dropped[0].hash, first);
    assert_eq!(dropped[1].hash, second);
    assert_eq!(dropped[2].hash, third);
    assert!(stager.contains(&protected));
    assert!(stager.contains(&incoming));
    assert_eq!(stager.received_len(), 2);
    assert_eq!(stager.received_bytes(), block_bytes.saturating_mul(2));
}

#[test]
fn insert_eviction_uses_fifo_order_for_same_instant_blocks() {
    let block = Network::Regtest.genesis_block();
    let serialized = bytes::Bytes::from(consensus_bytes(&block));
    let mut stager = BlockStager::new(default_sync_budget());
    let now = Instant::now();
    let first = Hash256::from_le_bytes(&[0x61; 32]);
    let second = Hash256::from_le_bytes(&[0x62; 32]);
    let third = Hash256::from_le_bytes(&[0x63; 32]);
    let incoming = Hash256::from_le_bytes(&[0x64; 32]);

    stager.insert(first, None, block.clone(), serialized.clone(), now);
    stager.insert(second, None, block.clone(), serialized.clone(), now);
    stager.insert(third, None, block.clone(), serialized.clone(), now);
    stager.budget.max_received_blocks = 2;

    let dropped = match stager.insert(incoming, None, block, serialized, now) {
        super::StagedBlock::AlreadyStaged => {
            panic!("incoming block should not already be staged")
        }
        super::StagedBlock::Memory { dropped, .. } => dropped,
        super::StagedBlock::DroppedForRetry { .. } => {
            panic!("incoming block should fit after evicting staged blocks")
        }
    };

    assert_eq!(dropped.len(), 2);
    assert_eq!(dropped[0].hash, first);
    assert_eq!(dropped[1].hash, second);
    assert!(!stager.contains(&first));
    assert!(!stager.contains(&second));
    assert!(stager.contains(&third));
    assert!(stager.contains(&incoming));
}

#[test]
fn insert_eviction_refreshes_received_deadline() {
    let block = Network::Regtest.genesis_block();
    let serialized = bytes::Bytes::from(consensus_bytes(&block));
    let mut budget = default_sync_budget();
    budget.max_received_blocks = 1;
    budget.received_timeout = Duration::from_secs(10);
    let mut stager = BlockStager::new(budget);
    let now = Instant::now();
    let old = Hash256::from_le_bytes(&[0x65; 32]);
    let fresh = Hash256::from_le_bytes(&[0x66; 32]);

    stager.insert(old, None, block.clone(), serialized.clone(), now);
    stager.insert(fresh, None, block, serialized, now + Duration::from_secs(5));

    assert_eq!(
        stager.next_received_deadline,
        Some(now + Duration::from_secs(15))
    );
    let dropped = stager.prune_expired(now + Duration::from_secs(10));

    assert!(dropped.is_empty());
    assert!(stager.contains(&fresh));
}

#[test]
fn insert_eviction_skips_stale_order_entries_after_drain() {
    let block = Network::Regtest.genesis_block();
    let serialized = bytes::Bytes::from(consensus_bytes(&block));
    let mut stager = BlockStager::new(default_sync_budget());
    let now = Instant::now();
    let first = Hash256::from_le_bytes(&[0x71; 32]);
    let second = Hash256::from_le_bytes(&[0x72; 32]);
    let third = Hash256::from_le_bytes(&[0x73; 32]);
    let incoming = Hash256::from_le_bytes(&[0x74; 32]);

    stager.insert(first, None, block.clone(), serialized.clone(), now);
    stager.insert(second, None, block.clone(), serialized.clone(), now);
    stager.insert(third, None, block.clone(), serialized.clone(), now);
    let drained = stager.drain_expected_prefix(&[first]);
    assert_eq!(drained.len(), 1);
    stager.budget.max_received_blocks = 2;

    let dropped = match stager.insert(incoming, None, block, serialized, now) {
        super::StagedBlock::AlreadyStaged => {
            panic!("incoming block should not already be staged")
        }
        super::StagedBlock::Memory { dropped, .. } => dropped,
        super::StagedBlock::DroppedForRetry { .. } => {
            panic!("incoming block should fit after evicting staged blocks")
        }
    };

    assert_eq!(dropped.len(), 1);
    assert_eq!(dropped[0].hash, second);
    assert!(!stager.contains(&first));
    assert!(!stager.contains(&second));
    assert!(stager.contains(&third));
    assert!(stager.contains(&incoming));
}
fn block_with_total_size(target: usize) -> Block {
    let probe = padded_block(target);
    let probe_size = block_size(&probe);
    let padding = target.saturating_mul(2).saturating_sub(probe_size);
    let block = padded_block(padding);
    assert_eq!(block_size(&block), target);
    block
}

fn padded_block(script_len: usize) -> Block {
    Block {
        header: Network::Regtest.genesis_block().header,
        txs: vec![Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::default(),
                script_sig: vec![0_u8; script_len].into(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(0),
                script_pubkey: Script::new(),
            }],
            lock_time: LockTime::ZERO,
        }],
    }
}

#[test]
fn full_window_of_estimate_sized_blocks_stages_without_eviction() {
    let budget = default_sync_budget();
    // Budget-pair consistency (R9): the staging byte budget admits a full
    // download window of blocks at the high-height per-slot estimate.
    assert_eq!(
        budget.max_received_bytes,
        budget
            .max_received_blocks
            .saturating_mul(bitcoin_rs_p2p::download_window::PENDING_BLOCK_BYTE_ESTIMATE)
    );
    let block = block_with_total_size(bitcoin_rs_p2p::download_window::PENDING_BLOCK_BYTE_ESTIMATE);
    let serialized = bytes::Bytes::from(consensus_bytes(&block));
    let mut stager = BlockStager::new(budget);
    let now = Instant::now();
    let window_slots = budget.max_received_blocks;

    for index in 0..window_slots {
        let mut raw = [0xee_u8; 32];
        let index_bytes = index.to_le_bytes();
        raw[..index_bytes.len()].copy_from_slice(&index_bytes);
        let hash = Hash256::from_le_bytes(&raw);
        match stager.insert(hash, None, block.clone(), serialized.clone(), now) {
            super::StagedBlock::Memory { dropped, .. } => {
                assert!(
                    dropped.is_empty(),
                    "full window must stage without eviction"
                );
            }
            other => panic!("estimate-sized block should stage in memory: {other:?}"),
        }
    }

    assert_eq!(stager.received_len(), window_slots);
    assert_eq!(stager.received_bytes(), budget.max_received_bytes);
}

#[test]
fn byte_budget_exhaustion_rejects_incoming_without_evicting_staged() {
    let block = Network::Regtest.genesis_block();
    let serialized = bytes::Bytes::from(consensus_bytes(&block));
    let block_bytes = block_size(&block);
    let mut budget = default_sync_budget();
    budget.max_received_bytes = block_bytes.saturating_mul(2);
    let mut stager = BlockStager::new(budget);
    let now = Instant::now();
    let expected = Hash256::from_le_bytes(&[0x01; 32]);
    let successor = Hash256::from_le_bytes(&[0x02; 32]);

    stager.insert(
        expected,
        Some(expected),
        block.clone(),
        serialized.clone(),
        now,
    );
    stager.insert(
        successor,
        Some(expected),
        block.clone(),
        serialized.clone(),
        now,
    );
    assert_eq!(stager.received_bytes(), budget.max_received_bytes);

    // Exhausted: every further non-expected block is refused outright —
    // backpressure, never evict/re-download churn of staged progress.
    for byte in [0x03_u8, 0x04] {
        let incoming = Hash256::from_le_bytes(&[byte; 32]);
        match stager.insert(
            incoming,
            Some(expected),
            block.clone(),
            serialized.clone(),
            now,
        ) {
            super::StagedBlock::DroppedForRetry { dropped } => {
                assert_eq!(dropped.hash, incoming);
            }
            other => panic!("exhausted stager should refuse incoming block: {other:?}"),
        }
        // Non-churn pin: zero staged blocks evicted while exhausted.
        assert_eq!(stager.received_len(), 2);
        assert!(stager.contains(&expected));
        assert!(stager.contains(&successor));
        assert_eq!(stager.received_bytes(), budget.max_received_bytes);
    }
}

#[test]
fn byte_budget_exhaustion_still_accepts_next_expected_block() {
    let block = Network::Regtest.genesis_block();
    let serialized = bytes::Bytes::from(consensus_bytes(&block));
    let block_bytes = block_size(&block);
    let mut budget = default_sync_budget();
    budget.max_received_bytes = block_bytes.saturating_mul(2);
    let mut stager = BlockStager::new(budget);
    let now = Instant::now();
    let expected = Hash256::from_le_bytes(&[0x0a; 32]);
    let successor_one = Hash256::from_le_bytes(&[0x0b; 32]);
    let successor_two = Hash256::from_le_bytes(&[0x0c; 32]);

    stager.insert(
        successor_one,
        Some(expected),
        block.clone(),
        serialized.clone(),
        now,
    );
    stager.insert(
        successor_two,
        Some(expected),
        block.clone(),
        serialized.clone(),
        now,
    );
    assert_eq!(stager.received_bytes(), budget.max_received_bytes);

    // The next expected block must stage even at byte exhaustion (bounded
    // overshoot) — refusing it would deadlock the apply frontier behind
    // the staged successors that hold the budget.
    match stager.insert(expected, Some(expected), block, serialized, now) {
        super::StagedBlock::Memory { dropped, .. } => {
            assert!(
                dropped.is_empty(),
                "expected block must not evict staged successors"
            );
        }
        other => panic!("next expected block should stage at exhaustion: {other:?}"),
    }
    assert_eq!(stager.received_len(), 3);
    assert!(stager.contains(&expected));
    assert!(stager.contains(&successor_one));
    assert!(stager.contains(&successor_two));
}

#[test]
fn received_order_compaction_bounds_stale_applied_entries() {
    let block = Network::Regtest.genesis_block();
    let serialized = bytes::Bytes::from(consensus_bytes(&block));
    let mut budget = default_sync_budget();
    budget.max_received_blocks = 1;
    let mut stager = BlockStager::new(budget);
    let now = Instant::now();

    for byte in 0x01_u8..0x60 {
        let hash = Hash256::from_le_bytes(&[byte; 32]);
        stager.insert(hash, None, block.clone(), serialized.clone(), now);
        let drained = stager.drain_expected_prefix(&[hash]);
        assert_eq!(drained.len(), 1);
    }

    assert_eq!(stager.received_len(), 0);
    assert!(stager.received_order_len() <= 32);

    let first = Hash256::from_le_bytes(&[0xa1; 32]);
    let second = Hash256::from_le_bytes(&[0xa2; 32]);
    stager.insert(first, None, block.clone(), serialized.clone(), now);
    let dropped = match stager.insert(second, None, block, serialized, now) {
        super::StagedBlock::AlreadyStaged => {
            panic!("incoming block should not already be staged")
        }
        super::StagedBlock::Memory { dropped, .. } => dropped,
        super::StagedBlock::DroppedForRetry { .. } => {
            panic!("incoming block should fit after evicting staged blocks")
        }
    };

    assert_eq!(dropped.len(), 1);
    assert_eq!(dropped[0].hash, first);
    assert!(stager.contains(&second));
}
