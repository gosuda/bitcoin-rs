use super::{
    Action, COUNTER_BOUND, CoinSet, FRAME_BOUND, JOB_SLOTS, MAX_ATTEMPTS, Phase, State,
    WindowDelta, safety, step, type_ok,
};

fn any_phase() -> Phase {
    let val: u8 = kani::any();
    kani::assume(val < 5);
    match val {
        0 => Phase::Idle,
        1 => Phase::Preparing,
        2 => Phase::Proved,
        3 => Phase::Committed,
        _ => Phase::Failed,
    }
}

fn any_coin_set() -> CoinSet {
    let bits: u16 = kani::any();
    CoinSet(bits & CoinSet::ALL_ROLES.0)
}

fn any_window_delta() -> WindowDelta {
    let len: u32 = kani::any();
    kani::assume(len <= COUNTER_BOUND);
    WindowDelta {
        len,
        created: any_coin_set(),
        spent: any_coin_set(),
        spent_internal: any_coin_set(),
        bip30_overwrites: any_coin_set(),
    }
}

fn bounded_counter(bound: u32) -> u32 {
    let val: u32 = kani::any();
    kani::assume(val <= bound);
    val
}

fn any_state() -> State {
    let sync_body: bool = kani::any();
    let sync_undo: bool = kani::any();
    let file_sync: bool = kani::any();
    let dir_sync: bool = kani::any();
    let cache_installed: bool = kani::any();
    let admission_closed: bool = kani::any();
    State {
        attempts: bounded_counter(MAX_ATTEMPTS),
        jobs: bounded_counter(JOB_SLOTS),
        proposed: bounded_counter(COUNTER_BOUND),
        committed: bounded_counter(COUNTER_BOUND),
        published: bounded_counter(COUNTER_BOUND),
        writer: bounded_counter(1),
        reader: bounded_counter(1),
        subscribed: bounded_counter(1),
        cursor: bounded_counter(COUNTER_BOUND),
        epoch: bounded_counter(COUNTER_BOUND),
        generation: bounded_counter(COUNTER_BOUND),
        prior_root: bounded_counter(COUNTER_BOUND),
        proposed_root: bounded_counter(COUNTER_BOUND),
        disk_root: bounded_counter(COUNTER_BOUND),
        live_root: bounded_counter(COUNTER_BOUND),
        body_pos: bounded_counter(FRAME_BOUND),
        undo_pos: bounded_counter(FRAME_BOUND),
        sync_body,
        sync_undo,
        file_sync,
        dir_sync,
        phase: any_phase(),
        window_delta: any_window_delta(),
        cache_installed,
        admission_closed,
        block_idx: bounded_counter(2),
        valid_prefix_len: bounded_counter(FRAME_BOUND),
        failed_block: bounded_counter(FRAME_BOUND),
        coin_store: any_coin_set(),
        coin_cache: any_coin_set(),
    }
}

fn any_action() -> Action {
    let idx: u8 = kani::any();
    kani::assume(idx < 23);
    let prefix_len: u32 = kani::any();
    kani::assume(prefix_len <= FRAME_BOUND + 1);
    let j: u32 = kani::any();
    kani::assume(j <= FRAME_BOUND + 1);
    match idx {
        0 => Action::StartJob,
        1 => Action::FinishJob,
        2 => Action::EvalBlock1,
        3 => Action::EvalBlock2,
        4 => Action::FailBlockJ { j },
        5 => Action::PrepareWindow { prefix_len },
        6 => Action::MarkBody,
        7 => Action::MarkUndo,
        8 => Action::SyncFile,
        9 => Action::SyncDirectory,
        10 => Action::CommitBatch,
        11 => Action::InstallCache,
        12 => Action::PublishPrefix,
        13 => Action::FailAmbiguous,
        14 => Action::FailBatch,
        15 => Action::Retry,
        16 => Action::Subscribe,
        17 => Action::Observe,
        18 => Action::AcquireWriter,
        19 => Action::ReleaseWriter,
        20 => Action::AcquireReader,
        21 => Action::ReleaseReader,
        _ => Action::Stutter,
    }
}

// RCV-02, SYNC-05
#[kani::proof]
fn check_init_safety() {
    let state = State::init();
    assert!(safety(&state));
    assert!(type_ok(&state));
}

// RCV-02, SYNC-05, WIN-03, CMT-02, CMT-03
#[kani::proof]
fn check_inductive_step() {
    let state = any_state();
    kani::assume(safety(&state));

    let action = any_action();
    if let Some(next) = step(&state, action) {
        assert!(safety(&next), "safety must be inductive: {action:?}");
        assert!(type_ok(&next), "TypeOK must be preserved: {action:?}");
    }
}

// CMT-02, CMT-03
#[kani::proof]
fn check_cache_install_before_commit_rejected() {
    let state = any_state();
    kani::assume(safety(&state));
    kani::assume(state.committed < state.window_delta.len);

    let next = step(&state, Action::InstallCache);
    assert!(next.is_none());
}

// CMT-02, CMT-03, CMT-05
#[kani::proof]
fn check_publish_without_commit_rejected() {
    let state = any_state();
    kani::assume(safety(&state));
    kani::assume(!state.cache_installed);

    let next = step(&state, Action::PublishPrefix);
    assert!(next.is_none());
}

// CMT-04
#[kani::proof]
fn check_ambiguous_failure_closes_admission() {
    let state = any_state();
    kani::assume(safety(&state));
    kani::assume(!state.admission_closed);

    if let Some(closed_state) = step(&state, Action::FailAmbiguous) {
        assert!(closed_state.admission_closed);
        assert!(step(&closed_state, Action::StartJob).is_none());
        assert!(step(&closed_state, Action::Retry).is_none());
    }
}

// WIN-06, WIN-08
#[kani::proof]
fn check_failure_at_block_j_commits_valid_prefix() {
    let state = any_state();
    kani::assume(safety(&state));
    let j: u32 = kani::any();
    kani::assume(j > 1 && j <= FRAME_BOUND);

    if let Some(next) = step(&state, Action::FailBlockJ { j }) {
        assert_eq!(next.failed_block, j);
        assert_eq!(next.valid_prefix_len, j - 1);
        assert!(next.valid_prefix_len < j);
        assert!(safety(&next));
    }
}

// WIN-03, WIN-06
#[kani::proof]
fn check_window_delta_bounds() {
    let state = any_state();
    kani::assume(safety(&state));

    let action = any_action();
    if let Some(next) = step(&state, action) {
        assert!(next.committed <= next.window_delta.len);
        assert!(next.window_delta.len <= next.proposed);
    }
}
