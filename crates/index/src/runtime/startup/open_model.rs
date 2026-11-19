//! Executable reference model for index store open helper ownership and lifecycle.

mod proofs;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum WorkerPhase {
    Idle,
    Opening,
    Ready,
    Serving,
    Stopping,
    Stopped,
    Abandoned,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum HelperPhase {
    Absent,
    Running,
    Exited,
    Joined,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum ResultKind {
    None,
    Opened,
    Failed,
    Panicked,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum HostOutcome {
    Pending,
    Clean,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct State {
    pub(crate) worker_phase: WorkerPhase,
    pub(crate) helper_phase: HelperPhase,
    pub(crate) shutdown_requested: bool,
    pub(crate) store_held: bool,
    pub(crate) result_kind: ResultKind,
    pub(crate) poisoned: bool,
    pub(crate) host_outcome: HostOutcome,
    pub(crate) checkpoint_published: bool,
}

impl State {
    #[must_use]
    pub(crate) const fn init() -> Self {
        Self {
            worker_phase: WorkerPhase::Idle,
            helper_phase: HelperPhase::Absent,
            shutdown_requested: false,
            store_held: false,
            result_kind: ResultKind::None,
            poisoned: false,
            host_outcome: HostOutcome::Pending,
            checkpoint_published: false,
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum Action {
    RequestShutdown,
    PreSpawnStop,
    SpawnHelper,
    NativeStoreAcquire,
    HelperPostSuccess,
    HelperPostFailed,
    HelperPostPanicked,
    HelperExit,
    WorkerReceiveOpened,
    WorkerStartServing,
    WorkerHandleFailed,
    WorkerCancelDuringOpening,
    WorkerCancelFromReadyOrServing,
    WorkerJoinHelper,
    WorkerCleanStop,
    WorkerStartupTimeout,
    HostDeadlineExpire,
    HostReportsAbandonment,
    HostCleanCompletion,
    PublishCheckpoint,
    Stutter,
}

#[must_use]
pub(crate) fn step(state: &State, action: Action) -> State {
    let mut next = state.clone();
    match action {
        Action::RequestShutdown => {
            if !state.shutdown_requested {
                next.shutdown_requested = true;
            }
        }
        Action::PreSpawnStop => {
            if state.worker_phase == WorkerPhase::Idle
                && state.shutdown_requested
                && state.helper_phase == HelperPhase::Absent
            {
                next.worker_phase = WorkerPhase::Stopped;
            }
        }
        Action::SpawnHelper => {
            if state.worker_phase == WorkerPhase::Idle
                && !state.shutdown_requested
                && state.helper_phase == HelperPhase::Absent
                && state.host_outcome == HostOutcome::Pending
            {
                next.worker_phase = WorkerPhase::Opening;
                next.helper_phase = HelperPhase::Running;
            }
        }
        Action::NativeStoreAcquire => {
            if state.helper_phase == HelperPhase::Running
                && !state.store_held
                && state.result_kind == ResultKind::None
            {
                next.store_held = true;
            }
        }
        Action::HelperPostSuccess => {
            if state.helper_phase == HelperPhase::Running
                && state.store_held
                && state.result_kind == ResultKind::None
            {
                next.result_kind = ResultKind::Opened;
            }
        }
        Action::HelperPostFailed => {
            if state.helper_phase == HelperPhase::Running && state.result_kind == ResultKind::None {
                next.result_kind = ResultKind::Failed;
                next.store_held = false;
            }
        }
        Action::HelperPostPanicked => {
            if state.helper_phase == HelperPhase::Running && state.result_kind == ResultKind::None {
                next.result_kind = ResultKind::Panicked;
                next.store_held = false;
            }
        }
        Action::HelperExit => {
            let eligible = state.helper_phase == HelperPhase::Running
                && ((state.worker_phase != WorkerPhase::Abandoned
                    && state.result_kind != ResultKind::None)
                    || state.worker_phase == WorkerPhase::Abandoned);
            if eligible {
                next.helper_phase = HelperPhase::Exited;
                if state.worker_phase == WorkerPhase::Abandoned {
                    next.store_held = false;
                }
            }
        }
        Action::WorkerReceiveOpened => {
            if state.worker_phase == WorkerPhase::Opening
                && state.result_kind == ResultKind::Opened
                && !state.shutdown_requested
            {
                next.worker_phase = WorkerPhase::Ready;
            }
        }
        Action::WorkerStartServing => {
            if state.worker_phase == WorkerPhase::Ready
                && state.helper_phase == HelperPhase::Joined
                && !state.shutdown_requested
            {
                next.worker_phase = WorkerPhase::Serving;
            }
        }
        Action::WorkerHandleFailed => {
            if state.worker_phase == WorkerPhase::Opening
                && (state.result_kind == ResultKind::Failed
                    || state.result_kind == ResultKind::Panicked)
                && !state.shutdown_requested
            {
                next.worker_phase = WorkerPhase::Stopping;
            }
        }
        Action::WorkerCancelDuringOpening => {
            if state.worker_phase == WorkerPhase::Opening && state.shutdown_requested {
                next.worker_phase = WorkerPhase::Stopping;
            }
        }
        Action::WorkerCancelFromReadyOrServing => {
            if (state.worker_phase == WorkerPhase::Ready
                || state.worker_phase == WorkerPhase::Serving)
                && state.shutdown_requested
            {
                next.worker_phase = WorkerPhase::Stopping;
            }
        }
        Action::WorkerJoinHelper => {
            if state.worker_phase != WorkerPhase::Abandoned
                && state.helper_phase == HelperPhase::Exited
            {
                next.helper_phase = HelperPhase::Joined;
            }
        }
        Action::WorkerCleanStop => {
            if state.worker_phase == WorkerPhase::Stopping
                && (state.helper_phase == HelperPhase::Absent
                    || state.helper_phase == HelperPhase::Joined)
            {
                next.worker_phase = WorkerPhase::Stopped;
                next.store_held = false;
            }
        }
        Action::WorkerStartupTimeout => {
            if state.worker_phase == WorkerPhase::Opening
                && !state.shutdown_requested
                && state.helper_phase == HelperPhase::Running
                && state.result_kind == ResultKind::None
            {
                next.worker_phase = WorkerPhase::Abandoned;
                next.poisoned = true;
            }
        }
        Action::HostDeadlineExpire => {
            if state.host_outcome == HostOutcome::Pending
                && state.shutdown_requested
                && state.worker_phase != WorkerPhase::Stopped
                && state.worker_phase != WorkerPhase::Abandoned
            {
                next.host_outcome = HostOutcome::Failed;
                next.poisoned = true;
            }
        }
        Action::HostReportsAbandonment => {
            let reports_failure = state.host_outcome == HostOutcome::Pending
                && (state.worker_phase == WorkerPhase::Abandoned
                    || (state.worker_phase == WorkerPhase::Stopped && state.poisoned));
            if reports_failure {
                next.host_outcome = HostOutcome::Failed;
                next.poisoned = true;
            }
        }
        Action::HostCleanCompletion => {
            if state.host_outcome == HostOutcome::Pending
                && state.worker_phase == WorkerPhase::Stopped
                && !state.poisoned
            {
                next.host_outcome = HostOutcome::Clean;
            }
        }
        Action::PublishCheckpoint => {
            if state.host_outcome == HostOutcome::Clean
                && !state.checkpoint_published
                && !state.poisoned
            {
                next.checkpoint_published = true;
            }
        }
        Action::Stutter => {}
    }
    next
}

fn is_stopped_worker_valid(state: &State) -> bool {
    if state.worker_phase != WorkerPhase::Stopped {
        return true;
    }
    (state.helper_phase == HelperPhase::Absent || state.helper_phase == HelperPhase::Joined)
        && !state.store_held
}

fn is_clean_host_valid(state: &State) -> bool {
    if state.host_outcome != HostOutcome::Clean {
        return true;
    }
    state.worker_phase == WorkerPhase::Stopped
}

fn is_serving_valid(state: &State) -> bool {
    if state.worker_phase != WorkerPhase::Serving {
        return true;
    }
    state.helper_phase == HelperPhase::Joined
}

fn is_checkpoint_valid(state: &State) -> bool {
    if !state.checkpoint_published {
        return true;
    }
    state.host_outcome == HostOutcome::Clean
        && !state.poisoned
        && !state.store_held
        && (state.helper_phase == HelperPhase::Absent || state.helper_phase == HelperPhase::Joined)
}

fn is_prespawn_valid(state: &State) -> bool {
    if state.worker_phase != WorkerPhase::Stopped || state.helper_phase != HelperPhase::Absent {
        return true;
    }
    !state.store_held && state.result_kind == ResultKind::None
}

fn is_abandoned_valid(state: &State) -> bool {
    let unrecoverable = state.poisoned
        || state.worker_phase == WorkerPhase::Abandoned
        || state.host_outcome == HostOutcome::Failed;
    if !unrecoverable {
        return true;
    }
    state.host_outcome != HostOutcome::Clean && !state.checkpoint_published
}

fn is_poison_coherence_valid(state: &State) -> bool {
    if state.worker_phase == WorkerPhase::Abandoned && !state.poisoned {
        return false;
    }
    if state.host_outcome == HostOutcome::Failed && !state.poisoned {
        return false;
    }
    true
}

fn is_store_valid(state: &State) -> bool {
    if !state.store_held {
        return true;
    }
    state.helper_phase != HelperPhase::Absent
}

fn is_helper_absent_valid(state: &State) -> bool {
    if state.helper_phase != HelperPhase::Absent {
        return true;
    }
    state.result_kind == ResultKind::None && !state.store_held
}

// EMB-01
#[must_use]
pub(crate) fn safety(state: &State) -> bool {
    is_stopped_worker_valid(state)
        && is_clean_host_valid(state)
        && is_serving_valid(state)
        && is_checkpoint_valid(state)
        && is_prespawn_valid(state)
        && is_abandoned_valid(state)
        && is_poison_coherence_valid(state)
        && is_store_valid(state)
        && is_helper_absent_valid(state)
}
