//! Kani formal verification harnesses for CommittedFactsHandoff and IndexGenerations.

use super::generations::{
    GenerationAction, GenerationsState, MAX_REORGS, MAX_TIP, TAIL_BOUND, logical_entry_bulk,
    logical_entry_live, safety as generations_safety, step as generations_step,
    step_missing_deep_reorg_guard,
};
use super::handoff::{
    HandoffAction, HandoffState, MAX_HEIGHT, MAX_VERIFIED, QUEUE_BUDGET, WakeMessage,
    safety as handoff_safety, step as handoff_step, step_mutant_wake_with_payload,
    step_unbounded_queue,
};

fn any_handoff_state() -> HandoffState {
    let applied_height: u32 = kani::any();
    let verified_height: u32 = kani::any();
    let coverage_height: u32 = kani::any();
    let queue_len_raw: u8 = kani::any();
    let queue_bytes_raw: u8 = kani::any();
    let gap: bool = kani::any();
    let wake_pending: bool = kani::any();
    let live_body_reads: u64 = kani::any();
    let recovery_body_reads: u64 = kani::any();
    let reorg_count: u32 = kani::any();

    kani::assume(applied_height <= MAX_HEIGHT);
    kani::assume(verified_height <= MAX_VERIFIED);
    kani::assume(coverage_height <= MAX_HEIGHT);
    let queue_bytes = usize::from(queue_bytes_raw);
    let queue_len = usize::from(queue_len_raw);
    kani::assume(queue_bytes <= QUEUE_BUDGET);
    kani::assume(queue_len <= QUEUE_BUDGET);
    kani::assume(live_body_reads == 0);
    kani::assume(recovery_body_reads <= u64::from(2 * MAX_HEIGHT));
    kani::assume(reorg_count <= 1);

    HandoffState {
        applied_height,
        verified_height,
        coverage_height,
        queue_len,
        queue_bytes,
        gap,
        wake_pending,
        last_wake_message: wake_pending.then_some(WakeMessage::Signal),
        live_body_reads,
        recovery_body_reads,
        reorg_count,
    }
}

fn any_handoff_action() -> HandoffAction {
    let disc: u8 = kani::any();
    kani::assume(disc < 6);
    match disc {
        0 => HandoffAction::CommitBlock,
        1 => HandoffAction::VerifyHistorical,
        2 => HandoffAction::WorkerLiveStep,
        3 => HandoffAction::WorkerRecoveryStep,
        4 => {
            let fork: u32 = kani::any();
            kani::assume(fork <= MAX_HEIGHT);
            HandoffAction::Reorganize { fork }
        }
        _ => HandoffAction::Stutter,
    }
}

fn any_non_reorg_handoff_action() -> HandoffAction {
    let disc: u8 = kani::any();
    kani::assume(disc < 5);
    match disc {
        0 => HandoffAction::CommitBlock,
        1 => HandoffAction::VerifyHistorical,
        2 => HandoffAction::WorkerLiveStep,
        3 => HandoffAction::WorkerRecoveryStep,
        _ => HandoffAction::Stutter,
    }
}

fn any_generations_state() -> GenerationsState {
    let applied_tip: u32 = kani::any();
    let tail_lo: u32 = kani::any();
    let tail_hi: u32 = kani::any();
    let active_gens_cover: u32 = kani::any();
    let has_invalid_coverage: bool = kani::any();
    let has_segment_offset: bool = kani::any();
    let reorg_count: u32 = kani::any();

    kani::assume(applied_tip <= MAX_TIP);
    kani::assume(tail_lo >= 1 && tail_lo <= MAX_TIP + 2);
    kani::assume(tail_hi <= MAX_TIP);
    kani::assume(active_gens_cover <= MAX_TIP);
    kani::assume(reorg_count <= MAX_REORGS);

    GenerationsState {
        applied_tip,
        tail_lo,
        tail_hi,
        active_gens_cover,
        has_invalid_coverage,
        has_segment_offset,
        reorg_count,
    }
}

fn any_generation_action() -> GenerationAction {
    let disc: u8 = kani::any();
    kani::assume(disc < 5);
    match disc {
        0 => GenerationAction::AppendBlock,
        1 => GenerationAction::SealGeneration,
        2 => {
            let fork: u32 = kani::any();
            kani::assume(fork <= MAX_TIP);
            GenerationAction::Reorganize { fork }
        }
        3 => GenerationAction::QueryAnswer,
        _ => GenerationAction::Stutter,
    }
}

// PRJ-01, PRJ-02, PRJ-04, PRJ-13, IDX-08
#[kani::proof]
fn harness_handoff_step_inductive_safety() {
    let s = any_handoff_state();
    kani::assume(handoff_safety(&s));
    let a = any_handoff_action();
    let next = handoff_step(&s, a);
    assert!(handoff_safety(&next));
}

// PRJ-01
#[kani::proof]
fn harness_live_path_reads_zero_block_bodies() {
    let s = any_handoff_state();
    kani::assume(handoff_safety(&s));
    kani::assume(!s.gap && s.queue_len > 0);
    let next = handoff_step(&s, HandoffAction::WorkerLiveStep);
    assert_eq!(next.live_body_reads, 0);
    assert_eq!(next.coverage_height, s.coverage_height + 1);
}

// PRJ-04
#[kani::proof]
fn harness_queue_overflow_drops_facts_and_sets_gap() {
    let s = any_handoff_state();
    kani::assume(handoff_safety(&s));
    kani::assume(s.queue_bytes == QUEUE_BUDGET && s.applied_height < MAX_HEIGHT);
    let next = handoff_step(&s, HandoffAction::CommitBlock);
    assert!(next.gap);
    assert_eq!(next.queue_bytes, QUEUE_BUDGET);
    assert_eq!(next.queue_len, s.queue_len);
}

// PRJ-02
#[kani::proof]
fn harness_recovery_path_reads_bodies_until_caught_up() {
    let s = any_handoff_state();
    kani::assume(handoff_safety(&s));
    kani::assume(s.gap && s.coverage_height < s.applied_height);
    let next = handoff_step(&s, HandoffAction::WorkerRecoveryStep);
    assert_eq!(next.recovery_body_reads, s.recovery_body_reads + 1);
    assert_eq!(next.gap, next.coverage_height != next.applied_height);
}

// PRJ-13
#[kani::proof]
fn harness_three_positions_independent_and_monotonic() {
    let s = any_handoff_state();
    kani::assume(handoff_safety(&s));
    let action = any_non_reorg_handoff_action();
    let next = handoff_step(&s, action);
    assert!(next.applied_height >= s.applied_height);
    assert!(next.verified_height >= s.verified_height);
    assert!(next.coverage_height >= s.coverage_height);
}

// IDX-08
#[kani::proof]
fn harness_wake_notification_carries_no_payload() {
    let s = any_handoff_state();
    kani::assume(handoff_safety(&s));
    let action = any_handoff_action();
    let next = handoff_step(&s, action);
    if s.applied_height < MAX_HEIGHT && matches!(action, HandoffAction::CommitBlock) {
        assert!(next.wake_pending);
    }
    if let Some(msg) = next.last_wake_message {
        assert!(!msg.carries_payload());
    }
}

// IDX-08
#[kani::proof]
#[kani::should_panic]
fn harness_negative_control_wake_carries_payload() {
    let s = any_handoff_state();
    kani::assume(handoff_safety(&s));
    kani::assume(s.applied_height < MAX_HEIGHT);
    let next = step_mutant_wake_with_payload(&s, HandoffAction::CommitBlock);
    assert!(next.wake_pending);
    let msg = next.last_wake_message.expect("wake message sent");
    assert!(!msg.carries_payload());
}

// PRJ-04
#[kani::proof]
fn harness_handoff_negative_control_unbounded_queue() {
    let s = any_handoff_state();
    kani::assume(handoff_safety(&s));
    kani::assume(s.queue_bytes == QUEUE_BUDGET && s.applied_height < MAX_HEIGHT);
    let next = step_unbounded_queue(&s, HandoffAction::CommitBlock);
    assert!(!handoff_safety(&next));
    assert!(next.queue_bytes > QUEUE_BUDGET);
}

// PRJ-05, PRJ-07, PRJ-09, REO-04, REO-05
#[kani::proof]
fn harness_generations_step_inductive_safety() {
    let s = any_generations_state();
    kani::assume(generations_safety(&s));
    let a = any_generation_action();
    let next = generations_step(&s, a);
    assert!(generations_safety(&next));
}

// PRJ-05
#[kani::proof]
fn harness_sealed_segment_immutability_and_tail_boundary() {
    let s = any_generations_state();
    kani::assume(
        generations_safety(&s) && s.tail_hi >= s.tail_lo && s.tail_hi - s.tail_lo + 1 >= TAIL_BOUND,
    );
    let next = generations_step(&s, GenerationAction::SealGeneration);
    assert_eq!(next.active_gens_cover, s.tail_lo + TAIL_BOUND - 1);
    assert_eq!(next.tail_lo, next.active_gens_cover + 1);
    assert!(next.active_gens_cover <= next.applied_tip);
}

// REO-04
#[kani::proof]
fn harness_deep_reorg_retires_invalidated_generations() {
    let s = any_generations_state();
    let fork: u32 = kani::any();
    kani::assume(
        generations_safety(&s)
            && s.reorg_count < MAX_REORGS
            && fork < s.tail_lo
            && fork < s.applied_tip,
    );
    let next = generations_step(&s, GenerationAction::Reorganize { fork });
    assert!(next.active_gens_cover <= fork);
    assert!(!next.has_invalid_coverage);
}

// REO-05
#[kani::proof]
fn harness_shallow_reorg_preserves_sealed_generations() {
    let s = any_generations_state();
    let fork: u32 = kani::any();
    kani::assume(
        generations_safety(&s)
            && s.reorg_count < MAX_REORGS
            && fork >= s.tail_lo
            && fork < s.applied_tip,
    );
    let next = generations_step(&s, GenerationAction::Reorganize { fork });
    assert_eq!(next.active_gens_cover, s.active_gens_cover);
    assert_eq!(next.tail_hi, fork);
}

// PRJ-09
#[kani::proof]
fn harness_bulk_and_live_logical_equivalence() {
    let height: u32 = kani::any();
    kani::assume(height <= MAX_TIP);
    let live = logical_entry_live(height);
    let bulk = logical_entry_bulk(height);
    assert_eq!(live, bulk);
}

// PRJ-07
#[kani::proof]
fn harness_query_answers_contain_no_segment_offsets() {
    let s = any_generations_state();
    kani::assume(generations_safety(&s) && s.applied_tip > 0);
    let next = generations_step(&s, GenerationAction::QueryAnswer);
    assert!(!next.has_segment_offset);
}

// REO-04
#[kani::proof]
fn harness_generations_negative_control_unretired_segment() {
    let s = any_generations_state();
    let fork: u32 = kani::any();
    kani::assume(
        generations_safety(&s)
            && s.reorg_count < MAX_REORGS
            && s.applied_tip > 0
            && fork < s.applied_tip
            && fork < s.tail_lo
            && s.active_gens_cover > fork,
    );
    let next = step_missing_deep_reorg_guard(&s, GenerationAction::Reorganize { fork });
    assert!(!generations_safety(&next));
    assert!(next.active_gens_cover > next.applied_tip);
}
