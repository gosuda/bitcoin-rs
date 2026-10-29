use bitcoin_rs_primitives::{
    Amount, Block, BlockPayload, Hash256, LockTime, Network, OutPoint, Script, Sequence, Tx, TxIn,
    TxOut, Witness, consensus_bytes,
};
use std::time::{Duration, Instant};

use super::BlockStager;
use crate::default_sync_budget;
use crate::download_window::SyncBudget;

#[test]
fn drain_expected_prefix_stops_at_first_missing_hash() {
    let block = Network::Regtest.genesis_block();
    let block_bytes = block.total_size();
    let mut stager = BlockStager::new(default_sync_budget(Network::Regtest));
    let now = std::time::Instant::now();
    let first = Hash256::from_le_bytes(&[0x01; 32]);
    let missing = Hash256::from_le_bytes(&[0x02; 32]);
    let third = Hash256::from_le_bytes(&[0x03; 32]);
    let fourth = Hash256::from_le_bytes(&[0x04; 32]);

    stager.insert(
        first,
        None,
        BlockPayload::from_local(block.clone()),
        None,
        now,
    );
    stager.insert(
        third,
        None,
        BlockPayload::from_local(block.clone()),
        None,
        now,
    );
    stager.insert(fourth, None, BlockPayload::from_local(block), None, now);

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
    let mut stager = BlockStager::new(default_sync_budget(Network::Regtest));
    stager.insert(
        hash,
        None,
        BlockPayload::from_local(block.clone()),
        None,
        Instant::now(),
    );

    let Some(loaded) = stager.staged_body(hash) else {
        panic!("inserted body must remain readable");
    };

    assert_eq!(loaded.block(), &block);
    assert_eq!(loaded.bytes(), &serialized);
    assert_eq!(stager.received_len(), 1);
    assert!(stager.contains(&hash));
}

#[test]
fn restore_many_restores_tail_byte_accounting() {
    let block = Network::Regtest.genesis_block();
    let block_bytes = block.total_size();
    let mut stager = BlockStager::new(default_sync_budget(Network::Regtest));
    let now = std::time::Instant::now();
    let first = Hash256::from_le_bytes(&[0x11; 32]);
    let second = Hash256::from_le_bytes(&[0x22; 32]);
    let third = Hash256::from_le_bytes(&[0x33; 32]);

    stager.insert(
        first,
        None,
        BlockPayload::from_local(block.clone()),
        None,
        now,
    );
    stager.insert(
        second,
        None,
        BlockPayload::from_local(block.clone()),
        None,
        now,
    );
    stager.insert(third, None, BlockPayload::from_local(block), None, now);
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
    let mut stager = BlockStager::new(default_sync_budget(Network::Regtest));
    let now = std::time::Instant::now();
    let staged = Hash256::from_le_bytes(&[0x31; 32]);
    let missing = Hash256::from_le_bytes(&[0x32; 32]);

    assert_eq!(stager.ready_received_len(None), None);

    stager.insert(staged, None, BlockPayload::from_local(block), None, now);

    assert_eq!(stager.ready_received_len(None), Some(1));
    assert_eq!(stager.ready_received_len(Some(staged)), Some(1));
    assert_eq!(stager.ready_received_len(Some(missing)), None);
}

#[test]
fn prune_expired_recomputes_deadline_after_dropping_oldest() {
    let block = Network::Regtest.genesis_block();
    let mut budget = default_sync_budget(Network::Regtest);
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
        BlockPayload::from_local(block.clone()),
        None,
        old_received_at,
    );
    stager.insert(
        fresh,
        None,
        BlockPayload::from_local(block),
        None,
        fresh_received_at,
    );

    let first_drop = stager.prune_expired(now);

    assert_eq!(first_drop.len(), 1);
    assert_eq!(first_drop[0], old);
    assert_eq!(stager.received_len(), 1);
    assert!(stager.contains(&fresh));

    let second_drop = stager.prune_expired(now + Duration::from_secs(1));

    assert_eq!(second_drop, Vec::<Hash256>::new());
    assert!(stager.contains(&fresh));

    let final_drop = stager.prune_expired(now + Duration::from_secs(10));

    assert_eq!(final_drop.len(), 1);
    assert_eq!(final_drop[0], fresh);
    assert_eq!(stager.received_len(), 0);
}

#[test]
fn prune_expired_releases_gate_pending_count() {
    let block = Network::Regtest.genesis_block();
    let mut budget = default_sync_budget(Network::Regtest);
    budget.received_timeout = Duration::from_secs(10);
    let mut stager = BlockStager::new(budget);
    let now = Instant::now();
    let stale_received_at = now
        .checked_sub(Duration::from_secs(11))
        .unwrap_or_else(|| panic!("test instant underflow"));
    let hash = Hash256::from_le_bytes(&[0x43; 32]);

    stager.insert(
        hash,
        None,
        BlockPayload::from_local(block),
        None,
        stale_received_at,
    );
    stager.set_gate_pending(&hash);
    assert_eq!(stager.gate_pending_count(), 1);

    let dropped = stager.prune_expired(now);

    assert_eq!(dropped.len(), 1);
    assert_eq!(stager.gate_pending_count(), 0);
    assert_eq!(stager.received_len(), 0);
}

#[test]
fn duplicate_insert_keeps_original_staged_deadline() {
    let block = Network::Regtest.genesis_block();
    let block_bytes = block.total_size();
    let mut budget = default_sync_budget(Network::Regtest);
    budget.received_timeout = Duration::from_secs(10);
    let mut stager = BlockStager::new(budget);
    let now = Instant::now();
    let hash = Hash256::from_le_bytes(&[0x43; 32]);

    stager.insert(
        hash,
        None,
        BlockPayload::from_local(block.clone()),
        None,
        now,
    );
    stager.insert(
        hash,
        None,
        BlockPayload::from_local(block),
        None,
        now + Duration::from_secs(5),
    );

    assert_eq!(stager.received_len(), 1);
    assert_eq!(stager.received_bytes(), block_bytes);

    let dropped = stager.prune_expired(now + Duration::from_secs(10));

    assert_eq!(dropped.len(), 1);
    assert_eq!(dropped[0], hash);
    assert_eq!(stager.received_len(), 0);
    assert_eq!(stager.received_bytes(), 0);
}

#[test]
fn insert_eviction_drops_oldest_unprotected_until_budget_fits() {
    let block = Network::Regtest.genesis_block();
    let block_bytes = block.total_size();
    let mut stager = BlockStager::new(default_sync_budget(Network::Regtest));
    let now = Instant::now();
    let protected = Hash256::from_le_bytes(&[0x51; 32]);
    let first = Hash256::from_le_bytes(&[0x52; 32]);
    let second = Hash256::from_le_bytes(&[0x53; 32]);
    let third = Hash256::from_le_bytes(&[0x54; 32]);
    let incoming = Hash256::from_le_bytes(&[0x55; 32]);

    stager.insert(
        protected,
        None,
        BlockPayload::from_local(block.clone()),
        None,
        now,
    );
    stager.insert(
        first,
        None,
        BlockPayload::from_local(block.clone()),
        None,
        now + Duration::from_secs(1),
    );
    stager.insert(
        second,
        None,
        BlockPayload::from_local(block.clone()),
        None,
        now + Duration::from_secs(2),
    );
    stager.insert(
        third,
        None,
        BlockPayload::from_local(block.clone()),
        None,
        now + Duration::from_secs(3),
    );
    stager.budget.max_received_blocks = 2;

    let dropped = match stager.insert(
        incoming,
        Some(protected),
        BlockPayload::from_local(block),
        None,
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
    assert_eq!(dropped[0], first);
    assert_eq!(dropped[1], second);
    assert_eq!(dropped[2], third);
    assert!(stager.contains(&protected));
    assert!(stager.contains(&incoming));
    assert_eq!(stager.received_len(), 2);
    assert_eq!(stager.received_bytes(), block_bytes.saturating_mul(2));
}

#[test]
fn insert_eviction_uses_fifo_order_for_same_instant_blocks() {
    let block = Network::Regtest.genesis_block();
    let mut stager = BlockStager::new(default_sync_budget(Network::Regtest));
    let now = Instant::now();
    let first = Hash256::from_le_bytes(&[0x61; 32]);
    let second = Hash256::from_le_bytes(&[0x62; 32]);
    let third = Hash256::from_le_bytes(&[0x63; 32]);
    let incoming = Hash256::from_le_bytes(&[0x64; 32]);

    stager.insert(
        first,
        None,
        BlockPayload::from_local(block.clone()),
        None,
        now,
    );
    stager.insert(
        second,
        None,
        BlockPayload::from_local(block.clone()),
        None,
        now,
    );
    stager.insert(
        third,
        None,
        BlockPayload::from_local(block.clone()),
        None,
        now,
    );
    stager.budget.max_received_blocks = 2;

    let dropped = match stager.insert(incoming, None, BlockPayload::from_local(block), None, now) {
        super::StagedBlock::AlreadyStaged => {
            panic!("incoming block should not already be staged")
        }
        super::StagedBlock::Memory { dropped, .. } => dropped,
        super::StagedBlock::DroppedForRetry { .. } => {
            panic!("incoming block should fit after evicting staged blocks")
        }
    };
    assert_eq!(dropped.len(), 2);
    assert_eq!(dropped[0], first);
    assert_eq!(dropped[1], second);
    assert!(!stager.contains(&first));
    assert!(!stager.contains(&second));
    assert!(stager.contains(&third));
    assert!(stager.contains(&incoming));
}

#[test]
fn insert_eviction_refreshes_received_deadline() {
    let block = Network::Regtest.genesis_block();
    let mut budget = default_sync_budget(Network::Regtest);
    budget.max_received_blocks = 1;
    budget.received_timeout = Duration::from_secs(10);
    let mut stager = BlockStager::new(budget);
    let now = Instant::now();
    let old = Hash256::from_le_bytes(&[0x65; 32]);
    let fresh = Hash256::from_le_bytes(&[0x66; 32]);

    stager.insert(
        old,
        None,
        BlockPayload::from_local(block.clone()),
        None,
        now,
    );
    stager.insert(
        fresh,
        None,
        BlockPayload::from_local(block),
        None,
        now + Duration::from_secs(5),
    );

    assert_eq!(
        stager.next_received_deadline,
        Some(now + Duration::from_secs(15))
    );
    let dropped = stager.prune_expired(now + Duration::from_secs(10));

    assert_eq!(dropped, Vec::<Hash256>::new());
    assert!(stager.contains(&fresh));
}

#[test]
fn insert_eviction_skips_stale_order_entries_after_drain() {
    let block = Network::Regtest.genesis_block();
    let mut stager = BlockStager::new(default_sync_budget(Network::Regtest));
    let now = Instant::now();
    let first = Hash256::from_le_bytes(&[0x71; 32]);
    let second = Hash256::from_le_bytes(&[0x72; 32]);
    let third = Hash256::from_le_bytes(&[0x73; 32]);
    let incoming = Hash256::from_le_bytes(&[0x74; 32]);

    stager.insert(
        first,
        None,
        BlockPayload::from_local(block.clone()),
        None,
        now,
    );
    stager.insert(
        second,
        None,
        BlockPayload::from_local(block.clone()),
        None,
        now,
    );
    stager.insert(
        third,
        None,
        BlockPayload::from_local(block.clone()),
        None,
        now,
    );
    let drained = stager.drain_expected_prefix(&[first]);
    assert_eq!(drained.len(), 1);
    stager.budget.max_received_blocks = 2;

    let dropped = match stager.insert(incoming, None, BlockPayload::from_local(block), None, now) {
        super::StagedBlock::AlreadyStaged => {
            panic!("incoming block should not already be staged")
        }
        super::StagedBlock::Memory { dropped, .. } => dropped,
        super::StagedBlock::DroppedForRetry { .. } => {
            panic!("incoming block should fit after evicting staged blocks")
        }
    };

    assert_eq!(dropped.len(), 1);
    assert_eq!(dropped[0], second);
    assert!(!stager.contains(&first));
    assert!(!stager.contains(&second));
    assert!(stager.contains(&third));
    assert!(stager.contains(&incoming));
}
fn block_with_total_size(target: usize) -> Block {
    let probe = padded_block(target);
    let probe_size = probe.total_size();
    let padding = target.saturating_mul(2).saturating_sub(probe_size);
    let block = padded_block(padding);
    assert_eq!(block.total_size(), target);
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
    let budget = default_sync_budget(Network::Regtest);
    assert_eq!(
        budget.max_received_bytes,
        budget
            .max_received_blocks
            .saturating_mul(crate::download_window::PENDING_BLOCK_BYTE_ESTIMATE)
    );
    let block = block_with_total_size(crate::download_window::PENDING_BLOCK_BYTE_ESTIMATE);
    let mut stager = BlockStager::new(budget);
    let now = Instant::now();
    let window_slots = budget.max_received_blocks;

    for index in 0..window_slots {
        let mut raw = [0xee; 32];
        let index_bytes = index.to_le_bytes();
        raw[..index_bytes.len()].copy_from_slice(&index_bytes);
        let hash = Hash256::from_le_bytes(&raw);
        match stager.insert(
            hash,
            None,
            BlockPayload::from_local(block.clone()),
            None,
            now,
        ) {
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
    let block_bytes = block.total_size();
    let mut budget = default_sync_budget(Network::Regtest);
    budget.max_received_bytes = block_bytes.saturating_mul(2);
    let mut stager = BlockStager::new(budget);
    let now = Instant::now();
    let expected = Hash256::from_le_bytes(&[0x01; 32]);
    let successor = Hash256::from_le_bytes(&[0x02; 32]);

    stager.insert(
        expected,
        Some(expected),
        BlockPayload::from_local(block.clone()),
        None,
        now,
    );
    stager.insert(
        successor,
        Some(expected),
        BlockPayload::from_local(block.clone()),
        None,
        now,
    );
    assert_eq!(stager.received_bytes(), budget.max_received_bytes);

    for byte in [0x03_u8, 0x04] {
        let incoming = Hash256::from_le_bytes(&[byte; 32]);
        match stager.insert(
            incoming,
            Some(expected),
            BlockPayload::from_local(block.clone()),
            None,
            now,
        ) {
            super::StagedBlock::DroppedForRetry { hash } => {
                assert_eq!(hash, incoming);
            }
            other => panic!("exhausted stager should refuse incoming block: {other:?}"),
        }
        assert_eq!(stager.received_len(), 2);
        assert!(stager.contains(&expected));
        assert!(stager.contains(&successor));
        assert_eq!(stager.received_bytes(), budget.max_received_bytes);
    }
}

#[test]
fn byte_budget_exhaustion_still_accepts_next_expected_block() {
    let block = Network::Regtest.genesis_block();
    let block_bytes = block.total_size();
    let mut budget = default_sync_budget(Network::Regtest);
    budget.max_received_bytes = block_bytes.saturating_mul(2);
    let mut stager = BlockStager::new(budget);
    let now = Instant::now();
    let expected = Hash256::from_le_bytes(&[0x0a; 32]);
    let successor_one = Hash256::from_le_bytes(&[0x0b; 32]);
    let successor_two = Hash256::from_le_bytes(&[0x0c; 32]);

    stager.insert(
        successor_one,
        Some(expected),
        BlockPayload::from_local(block.clone()),
        None,
        now,
    );
    stager.insert(
        successor_two,
        Some(expected),
        BlockPayload::from_local(block.clone()),
        None,
        now,
    );
    assert_eq!(stager.received_bytes(), budget.max_received_bytes);

    match stager.insert(
        expected,
        Some(expected),
        BlockPayload::from_local(block),
        None,
        now,
    ) {
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
    let mut budget = default_sync_budget(Network::Regtest);
    budget.max_received_blocks = 1;
    let mut stager = BlockStager::new(budget);
    let now = Instant::now();

    for byte in 0x01_u8..0x60 {
        let hash = Hash256::from_le_bytes(&[byte; 32]);
        stager.insert(
            hash,
            None,
            BlockPayload::from_local(block.clone()),
            None,
            now,
        );
        let drained = stager.drain_expected_prefix(&[hash]);
        assert_eq!(drained.len(), 1);
    }

    assert_eq!(stager.received_len(), 0);
    assert!(stager.received_order_len() <= 32);

    let first = Hash256::from_le_bytes(&[0xa1; 32]);
    let second = Hash256::from_le_bytes(&[0xa2; 32]);
    stager.insert(
        first,
        None,
        BlockPayload::from_local(block.clone()),
        None,
        now,
    );
    let dropped = match stager.insert(second, None, BlockPayload::from_local(block), None, now) {
        super::StagedBlock::AlreadyStaged => {
            panic!("incoming block should not already be staged")
        }
        super::StagedBlock::Memory { dropped, .. } => dropped,
        super::StagedBlock::DroppedForRetry { .. } => {
            panic!("incoming block should fit after evicting staged blocks")
        }
    };
    assert_eq!(dropped.len(), 1);
    assert_eq!(dropped[0], first);
    assert!(stager.contains(&second));
}

#[test]
fn insert_evicts_same_height_fork_before_expected_hash() {
    let expected_hash = Hash256::from_le_bytes(&[0x11; 32]);
    let fork_hash = Hash256::from_le_bytes(&[0x22; 32]);
    let mut stager = BlockStager::new(SyncBudget {
        max_received_blocks: 1,
        max_received_bytes: usize::MAX,
        ..default_sync_budget(Network::Regtest)
    });
    let now = Instant::now();
    let block = Network::Regtest.genesis_block();

    let super::StagedBlock::Memory { dropped, .. } = stager.insert(
        fork_hash,
        Some(expected_hash),
        BlockPayload::from_local(block.clone()),
        None,
        now,
    ) else {
        panic!("fork block should stage");
    };
    assert_eq!(dropped, Vec::<Hash256>::new());

    let super::StagedBlock::Memory { dropped, .. } = stager.insert(
        expected_hash,
        Some(expected_hash),
        BlockPayload::from_local(block),
        None,
        now,
    ) else {
        panic!("expected block should stage");
    };
    assert_eq!(dropped.len(), 1);
    assert_eq!(dropped[0], fork_hash);
    assert_eq!(stager.received_len(), 1);
    assert!(stager.contains(&expected_hash));
}

fn lean_and_fat_blocks() -> (Block, Block, bytes::Bytes) {
    let genesis = Network::Regtest.genesis_block();
    let serialized = bytes::Bytes::from(consensus_bytes(&genesis));
    let lean = genesis.clone();
    let mut fat = genesis;
    fat.txs.reserve_exact(64);
    assert!(fat.retained_heap_bytes() > lean.retained_heap_bytes());
    (lean, fat, serialized)
}

#[test]
fn decoded_attribution_follows_insert_drain_and_restore_apart_from_serialized_bytes() {
    let (lean, fat, serialized) = lean_and_fat_blocks();
    let wire = serialized.len();
    let lean_bytes = lean.retained_heap_bytes();
    let fat_bytes = fat.retained_heap_bytes();
    let mut stager = BlockStager::new(default_sync_budget(Network::Regtest));
    let now = Instant::now();
    let first = Hash256::from_le_bytes(&[0x81; 32]);
    let second = Hash256::from_le_bytes(&[0x82; 32]);
    assert_eq!(stager.decoded_bytes(), 0);
    assert_eq!(stager.retained_attributed_bytes(), 0);
    assert_eq!(stager.retained_attributed_bytes_high_water(), 0);

    stager.insert(first, None, BlockPayload::from_local(lean), None, now);
    stager.insert(second, None, BlockPayload::from_local(fat), None, now);

    let peak = lean_bytes + fat_bytes + 2 * wire;
    assert_eq!(stager.received_bytes(), 2 * wire);
    assert_eq!(stager.decoded_bytes(), lean_bytes + fat_bytes);
    assert_eq!(stager.retained_attributed_bytes(), peak);
    assert_eq!(stager.retained_attributed_bytes_high_water(), peak);

    let mut drained = stager.drain_expected_prefix(&[first, second]);
    assert_eq!(drained.len(), 2);
    assert_eq!(stager.received_len(), 0);
    assert_eq!(stager.received_bytes(), 0);
    assert_eq!(stager.decoded_bytes(), 0);
    assert_eq!(stager.retained_attributed_bytes(), 0);
    assert_eq!(stager.retained_attributed_bytes_high_water(), peak);

    let fat_tail = drained.split_off(1);
    let clone = fat_tail[0].clone();
    let clone_bytes = clone.payload().block().retained_heap_bytes();
    assert!(clone_bytes < fat_bytes);
    assert_eq!(
        fat_tail[0].payload().block().retained_heap_bytes(),
        fat_bytes
    );
    stager.restore_many([clone]);
    assert_eq!(stager.received_len(), 1);
    assert_eq!(stager.received_bytes(), wire);
    assert_eq!(stager.decoded_bytes(), clone_bytes);
    assert_eq!(stager.retained_attributed_bytes(), clone_bytes + wire);
    assert_eq!(stager.retained_attributed_bytes_high_water(), peak);

    stager.restore_many(drained);
    assert_eq!(stager.received_len(), 2);
    assert_eq!(stager.received_bytes(), 2 * wire);
    assert_eq!(stager.decoded_bytes(), clone_bytes + lean_bytes);
    assert_eq!(
        stager.retained_attributed_bytes(),
        clone_bytes + lean_bytes + 2 * wire
    );
    assert_eq!(stager.retained_attributed_bytes_high_water(), peak);

    let drained = stager.drain_expected_prefix(&[first, second]);
    assert_eq!(drained.len(), 2);
    assert_eq!(stager.received_bytes(), 0);
    assert_eq!(stager.decoded_bytes(), 0);
    assert_eq!(stager.retained_attributed_bytes(), 0);
    assert_eq!(stager.retained_attributed_bytes_high_water(), peak);
}

#[test]
fn restore_refilling_past_the_earlier_peak_advances_only_the_retained_high_water_mark() {
    let (lean, fat, serialized) = lean_and_fat_blocks();
    let wire = serialized.len();
    let lean_bytes = lean.retained_heap_bytes();
    let fat_bytes = fat.retained_heap_bytes();
    let mut stager = BlockStager::new(default_sync_budget(Network::Regtest));
    let now = Instant::now();
    let parked = Hash256::from_le_bytes(&[0x91; 32]);
    let refill = Hash256::from_le_bytes(&[0x92; 32]);

    stager.insert(parked, None, BlockPayload::from_local(lean), None, now);
    let drained = stager.drain_expected_prefix(&[parked]);
    stager.insert(refill, None, BlockPayload::from_local(fat), None, now);
    assert_eq!(stager.received_high_water(), 1);
    assert_eq!(stager.received_bytes_high_water(), wire);
    assert_eq!(
        stager.retained_attributed_bytes_high_water(),
        fat_bytes + wire
    );

    stager.restore_many(drained);

    let combined = lean_bytes + fat_bytes + 2 * wire;
    assert_eq!(stager.retained_attributed_bytes(), combined);
    assert_eq!(stager.retained_attributed_bytes_high_water(), combined);
    assert_eq!(stager.received_bytes(), 2 * wire);
    assert_eq!(stager.received_bytes_high_water(), wire);
    assert_eq!(stager.received_high_water(), 1);
}

#[test]
fn restore_replacing_a_staged_entry_swaps_its_attribution() {
    let (lean, fat, serialized) = lean_and_fat_blocks();
    let wire = serialized.len();
    let lean_bytes = lean.retained_heap_bytes();
    let fat_bytes = fat.retained_heap_bytes();
    let mut stager = BlockStager::new(default_sync_budget(Network::Regtest));
    let now = Instant::now();
    let hash = Hash256::from_le_bytes(&[0xa1; 32]);

    stager.insert(hash, None, BlockPayload::from_local(fat), None, now);
    let drained = stager.drain_expected_prefix(&[hash]);
    stager.insert(hash, None, BlockPayload::from_local(lean), None, now);
    assert_eq!(stager.decoded_bytes(), lean_bytes);

    stager.restore_many(drained);

    assert_eq!(stager.received_len(), 1);
    assert_eq!(stager.received_bytes(), wire);
    assert_eq!(stager.decoded_bytes(), fat_bytes);
    assert_eq!(stager.retained_attributed_bytes(), fat_bytes + wire);
    assert_eq!(
        stager.retained_attributed_bytes_high_water(),
        fat_bytes + wire
    );

    let drained = stager.drain_expected_prefix(&[hash]);
    assert_eq!(drained.len(), 1);
    assert_eq!(stager.received_bytes(), 0);
    assert_eq!(stager.decoded_bytes(), 0);
    assert_eq!(stager.retained_attributed_bytes(), 0);
}

#[test]
fn prune_expired_releases_decoded_and_serialized_attribution() {
    let (lean, fat, serialized) = lean_and_fat_blocks();
    let wire = serialized.len();
    let lean_bytes = lean.retained_heap_bytes();
    let fat_bytes = fat.retained_heap_bytes();
    let mut budget = default_sync_budget(Network::Regtest);
    budget.received_timeout = Duration::from_secs(10);
    let mut stager = BlockStager::new(budget);
    let now = Instant::now();
    let stale_at = now
        .checked_sub(Duration::from_secs(11))
        .unwrap_or_else(|| panic!("test instant underflow"));
    let stale = Hash256::from_le_bytes(&[0xb1; 32]);
    let fresh = Hash256::from_le_bytes(&[0xb2; 32]);

    stager.insert(stale, None, BlockPayload::from_local(fat), None, stale_at);
    stager.insert(fresh, None, BlockPayload::from_local(lean), None, now);
    let peak = fat_bytes + lean_bytes + 2 * wire;
    assert_eq!(stager.retained_attributed_bytes_high_water(), peak);

    assert_eq!(stager.prune_expired(now), [stale]);
    assert_eq!(stager.received_bytes(), wire);
    assert_eq!(stager.decoded_bytes(), lean_bytes);
    assert_eq!(stager.retained_attributed_bytes(), lean_bytes + wire);

    assert_eq!(stager.prune_expired(now + Duration::from_secs(10)), [fresh]);
    assert_eq!(stager.received_bytes(), 0);
    assert_eq!(stager.decoded_bytes(), 0);
    assert_eq!(stager.retained_attributed_bytes(), 0);
    assert_eq!(stager.retained_attributed_bytes_high_water(), peak);
}

#[test]
fn eviction_discard_and_retire_release_attribution() {
    let (lean, fat, serialized) = lean_and_fat_blocks();
    let wire = serialized.len();
    let lean_bytes = lean.retained_heap_bytes();
    let fat_bytes = fat.retained_heap_bytes();
    let mut budget = default_sync_budget(Network::Regtest);
    budget.max_received_blocks = 1;
    let mut stager = BlockStager::new(budget);
    let now = Instant::now();
    let evicted = Hash256::from_le_bytes(&[0xc1; 32]);
    let kept = Hash256::from_le_bytes(&[0xc2; 32]);
    let retired = Hash256::from_le_bytes(&[0xc3; 32]);

    stager.insert(evicted, None, BlockPayload::from_local(fat), None, now);
    let super::StagedBlock::Memory { dropped, .. } = stager.insert(
        kept,
        None,
        BlockPayload::from_local(lean.clone()),
        None,
        now,
    ) else {
        panic!("incoming block should stage after evicting the older one");
    };
    assert_eq!(dropped, [evicted]);
    assert_eq!(
        stager.retained_attributed_bytes_high_water(),
        fat_bytes + lean_bytes + 2 * wire
    );
    assert_eq!(stager.received_bytes(), wire);
    assert_eq!(stager.decoded_bytes(), lean_bytes);
    assert_eq!(stager.retained_attributed_bytes(), lean_bytes + wire);

    assert!(stager.discard(&kept));
    assert_eq!(stager.received_bytes(), 0);
    assert_eq!(stager.decoded_bytes(), 0);
    assert_eq!(stager.retained_attributed_bytes(), 0);

    stager.insert(retired, None, BlockPayload::from_local(lean), None, now);
    assert_eq!(stager.decoded_bytes(), lean_bytes);
    assert!(stager.retire_applied(&retired));
    assert_eq!(stager.received_bytes(), 0);
    assert_eq!(stager.decoded_bytes(), 0);
    assert_eq!(stager.retained_attributed_bytes(), 0);
}

#[test]
fn duplicate_and_refused_inserts_leave_attribution_untouched() {
    let (lean, fat, serialized) = lean_and_fat_blocks();
    let wire = serialized.len();
    let lean_bytes = lean.retained_heap_bytes();
    let mut budget = default_sync_budget(Network::Regtest);
    budget.max_received_bytes = wire;
    let mut stager = BlockStager::new(budget);
    let now = Instant::now();
    let staged = Hash256::from_le_bytes(&[0xd1; 32]);
    let refused = Hash256::from_le_bytes(&[0xd2; 32]);

    stager.insert(staged, None, BlockPayload::from_local(lean), None, now);
    let settled = (
        stager.decoded_bytes(),
        stager.retained_attributed_bytes(),
        stager.retained_attributed_bytes_high_water(),
    );
    assert_eq!(settled, (lean_bytes, lean_bytes + wire, lean_bytes + wire));

    assert!(matches!(
        stager.insert(
            staged,
            None,
            BlockPayload::from_local(fat.clone()),
            None,
            now,
        ),
        super::StagedBlock::AlreadyStaged
    ));
    assert!(matches!(
        stager.insert(
            refused,
            Some(staged),
            BlockPayload::from_local(fat),
            None,
            now,
        ),
        super::StagedBlock::DroppedForRetry { .. }
    ));
    assert_eq!(
        (
            stager.decoded_bytes(),
            stager.retained_attributed_bytes(),
            stager.retained_attributed_bytes_high_water(),
        ),
        settled
    );
    assert_eq!(stager.received_bytes(), wire);
}
