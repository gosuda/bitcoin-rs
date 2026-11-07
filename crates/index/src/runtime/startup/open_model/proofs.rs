//! Kani formal verification harnesses for index store open helper ownership and lifecycle.

use super::{Action, HelperPhase, HostOutcome, ResultKind, State, WorkerPhase, safety, step};

fn any_worker_phase() -> WorkerPhase {
    let val: u8 = kani::any();
    kani::assume(val < 7);
    match val {
        0 => WorkerPhase::Idle,
        1 => WorkerPhase::Opening,
        2 => WorkerPhase::Ready,
        3 => WorkerPhase::Serving,
        4 => WorkerPhase::Stopping,
        5 => WorkerPhase::Stopped,
        _ => WorkerPhase::Abandoned,
    }
}

fn any_helper_phase() -> HelperPhase {
    let val: u8 = kani::any();
    kani::assume(val < 4);
    match val {
        0 => HelperPhase::Absent,
        1 => HelperPhase::Running,
        2 => HelperPhase::Exited,
        _ => HelperPhase::Joined,
    }
}

fn any_result_kind() -> ResultKind {
    let val: u8 = kani::any();
    kani::assume(val < 4);
    match val {
        0 => ResultKind::None,
        1 => ResultKind::Opened,
        2 => ResultKind::Failed,
        _ => ResultKind::Panicked,
    }
}

fn any_host_outcome() -> HostOutcome {
    let val: u8 = kani::any();
    kani::assume(val < 3);
    match val {
        0 => HostOutcome::Pending,
        1 => HostOutcome::Clean,
        _ => HostOutcome::Failed,
    }
}

fn any_action() -> Action {
    let val: u8 = kani::any();
    kani::assume(val < 21);
    match val {
        0 => Action::RequestShutdown,
        1 => Action::PreSpawnStop,
        2 => Action::SpawnHelper,
        3 => Action::NativeStoreAcquire,
        4 => Action::HelperPostSuccess,
        5 => Action::HelperPostFailed,
        6 => Action::HelperPostPanicked,
        7 => Action::HelperExit,
        8 => Action::WorkerReceiveOpened,
        9 => Action::WorkerStartServing,
        10 => Action::WorkerHandleFailed,
        11 => Action::WorkerCancelDuringOpening,
        12 => Action::WorkerCancelFromReadyOrServing,
        13 => Action::WorkerJoinHelper,
        14 => Action::WorkerCleanStop,
        15 => Action::WorkerStartupTimeout,
        16 => Action::HostDeadlineExpire,
        17 => Action::HostReportsAbandonment,
        18 => Action::HostCleanCompletion,
        19 => Action::PublishCheckpoint,
        _ => Action::Stutter,
    }
}

fn any_state() -> State {
    State {
        worker_phase: any_worker_phase(),
        helper_phase: any_helper_phase(),
        shutdown_requested: kani::any(),
        store_held: kani::any(),
        result_kind: any_result_kind(),
        poisoned: kani::any(),
        host_outcome: any_host_outcome(),
        checkpoint_published: kani::any(),
    }
}

// EMB-01
#[kani::proof]
fn init_satisfies_safety() {
    let state = State::init();
    assert!(safety(&state));
}

// EMB-01
#[kani::proof]
fn step_preserves_safety_induction() {
    let state = any_state();
    kani::assume(safety(&state));
    let action = any_action();
    let next = step(&state, action);
    assert!(safety(&next));
}

// EMB-01
#[kani::proof]
fn stopped_worker_requires_closed_helper_and_no_store() {
    let state = any_state();
    kani::assume(safety(&state));
    let action = any_action();
    let next = step(&state, action);
    if next.worker_phase == WorkerPhase::Stopped {
        assert!(
            next.helper_phase == HelperPhase::Absent || next.helper_phase == HelperPhase::Joined
        );
        assert!(!next.store_held);
    }
}

// EMB-01
#[kani::proof]
fn checkpoint_implies_clean_host_no_poison_no_store() {
    let state = any_state();
    kani::assume(safety(&state));
    let action = any_action();
    let next = step(&state, action);
    if next.checkpoint_published {
        assert_eq!(next.host_outcome, HostOutcome::Clean);
        assert!(!next.poisoned);
        assert!(!next.store_held);
        assert!(
            next.helper_phase == HelperPhase::Absent || next.helper_phase == HelperPhase::Joined
        );
    }
}

// EMB-01
#[kani::proof]
fn prespawn_stopped_never_started_io() {
    let state = any_state();
    kani::assume(safety(&state));
    let action = any_action();
    let next = step(&state, action);
    if next.worker_phase == WorkerPhase::Stopped && next.helper_phase == HelperPhase::Absent {
        assert!(!next.store_held);
        assert_eq!(next.result_kind, ResultKind::None);
    }
}

// EMB-01
#[kani::proof]
fn abandoned_or_failed_never_clean_or_checkpoint() {
    let state = any_state();
    kani::assume(safety(&state));
    let action = any_action();
    let next = step(&state, action);
    if next.poisoned
        || next.worker_phase == WorkerPhase::Abandoned
        || next.host_outcome == HostOutcome::Failed
    {
        assert_ne!(next.host_outcome, HostOutcome::Clean);
        assert!(!next.checkpoint_published);
    }
}

// EMB-01
#[kani::proof]
fn poison_and_failure_are_monotonic() {
    let state = any_state();
    kani::assume(safety(&state));
    let action = any_action();
    let next = step(&state, action);
    if state.poisoned {
        assert!(next.poisoned);
    }
    if state.host_outcome == HostOutcome::Failed {
        assert_eq!(next.host_outcome, HostOutcome::Failed);
    }
}

// EMB-01
#[kani::proof]
fn finite_trace_cancellation_reaches_clean_stop() {
    let mut state = State::init();
    assert!(safety(&state));

    state = step(&state, Action::SpawnHelper);
    assert!(safety(&state));
    assert_eq!(state.worker_phase, WorkerPhase::Opening);
    assert_eq!(state.helper_phase, HelperPhase::Running);

    state = step(&state, Action::NativeStoreAcquire);
    assert!(safety(&state));
    assert!(state.store_held);

    state = step(&state, Action::HelperPostSuccess);
    assert!(safety(&state));
    assert_eq!(state.result_kind, ResultKind::Opened);
    assert_eq!(state.helper_phase, HelperPhase::Running);

    state = step(&state, Action::WorkerReceiveOpened);
    assert!(safety(&state));
    assert_eq!(state.worker_phase, WorkerPhase::Ready);
    assert_eq!(state.helper_phase, HelperPhase::Running);

    state = step(&state, Action::RequestShutdown);
    assert!(safety(&state));
    assert!(state.shutdown_requested);

    state = step(&state, Action::WorkerCancelFromReadyOrServing);
    assert!(safety(&state));
    assert_eq!(state.worker_phase, WorkerPhase::Stopping);

    state = step(&state, Action::HelperExit);
    assert!(safety(&state));
    assert_eq!(state.helper_phase, HelperPhase::Exited);

    state = step(&state, Action::WorkerJoinHelper);
    assert!(safety(&state));
    assert_eq!(state.helper_phase, HelperPhase::Joined);

    state = step(&state, Action::WorkerCleanStop);
    assert!(safety(&state));
    assert_eq!(state.worker_phase, WorkerPhase::Stopped);
    assert!(!state.store_held);

    state = step(&state, Action::HostCleanCompletion);
    assert!(safety(&state));
    assert_eq!(state.host_outcome, HostOutcome::Clean);

    state = step(&state, Action::PublishCheckpoint);
    assert!(safety(&state));
    assert!(state.checkpoint_published);
}
