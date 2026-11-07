//! Executable reference model and Kani verification harnesses for ServingView query lifecycle.

use bitcoin_rs_primitives::Network;

pub(crate) const MAX_HEIGHT: u32 = 2;
pub(crate) const MAX_VIEWS: usize = 2;
pub(crate) const MAX_GENERATIONS: u64 = 2;

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub(crate) struct BlockHash(pub(crate) [u8; 32]);

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CapabilityCoverage {
    pub(crate) txindex: Option<u32>,
    pub(crate) scriptindex: Option<u32>,
    pub(crate) blockfilterindex: Option<u32>,
}

impl CapabilityCoverage {
    #[cfg(kani)]
    #[must_use]
    pub(crate) fn arbitrary() -> Self {
        Self {
            txindex: kani::any(),
            scriptindex: kani::any(),
            blockfilterindex: kani::any(),
        }
    }

    #[cfg(not(kani))]
    #[must_use]
    #[expect(dead_code, reason = "kani harness helper")]
    pub(crate) const fn arbitrary() -> Self {
        Self {
            txindex: Some(100),
            scriptindex: Some(100),
            blockfilterindex: Some(100),
        }
    }

    #[must_use]
    #[expect(dead_code, reason = "model invariant helper")]
    pub(crate) fn min_coverage(&self) -> u32 {
        let t = self.txindex.unwrap_or(0);
        let s = self.scriptindex.unwrap_or(0);
        let b = self.blockfilterindex.unwrap_or(0);
        t.min(s).min(b)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AppliedEpoch {
    pub(crate) chain_id: Network,
    pub(crate) tip_hash: BlockHash,
    pub(crate) tip_height: u32,
    pub(crate) commit_id: u64,
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub(crate) enum ViewStatus {
    #[default]
    None,
    Active,
    Expired,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ServingView {
    pub(crate) epoch: AppliedEpoch,
    pub(crate) generation_id: u64,
    pub(crate) coverage: CapabilityCoverage,
    pub(crate) status: ViewStatus,
    pub(crate) captured: bool,
}

impl ServingView {
    #[must_use]
    pub(crate) fn new(
        epoch: AppliedEpoch,
        generation_id: u64,
        coverage: CapabilityCoverage,
    ) -> Self {
        Self {
            epoch,
            generation_id,
            coverage,
            status: ViewStatus::Active,
            captured: true,
        }
    }

    pub(crate) fn query_tx_at_height(
        &self,
        target_height: u32,
    ) -> Result<QueryAnswer, TxQueryError> {
        let max_cov = self.coverage.txindex.unwrap_or(0);
        if target_height > max_cov {
            return Err(TxQueryError::Unavailable(
                TxUnavailableCause::OutsideCoverage {
                    declared_floor_or_tip: max_cov,
                },
            ));
        }
        Ok(QueryAnswer {
            height: self.epoch.tip_height,
            block_hash: self.epoch.tip_hash,
            coverage: self.coverage.clone(),
            payload: u64::from(target_height),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct QueryAnswer {
    pub(crate) height: u32,
    pub(crate) block_hash: BlockHash,
    pub(crate) coverage: CapabilityCoverage,
    pub(crate) payload: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum TxQueryError {
    #[error("transaction index changed during query; retry")]
    #[expect(dead_code, reason = "model error variant")]
    Retry(RetryReason),
    #[error("transaction index unavailable: {0:?}")]
    Unavailable(TxUnavailableCause),
    #[error("serving view expired due to generation retirement")]
    ExpiredView,
    #[error("transaction index storage error: {0}")]
    #[expect(dead_code, reason = "model error variant")]
    Storage(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[expect(dead_code, reason = "model error variant")]
pub(crate) enum RetryReason {
    TipMoved {
        expected_commit: u64,
        current_commit: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum TxUnavailableCause {
    OutsideCoverage { declared_floor_or_tip: u32 },
}

impl TxUnavailableCause {
    #[must_use]
    pub(crate) const fn declared_floor_or_tip(&self) -> u32 {
        match self {
            Self::OutsideCoverage {
                declared_floor_or_tip,
            } => *declared_floor_or_tip,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OccurrenceCursor {
    pub(crate) generation_id: u64,
    pub(crate) height: u32,
    pub(crate) tx_pos: u32,
}

#[derive(Clone, Debug)]
pub(crate) struct MockIndexEngine {
    pub(crate) current_generation: u64,
}

impl MockIndexEngine {
    #[must_use]
    pub(crate) const fn with_generation(current_gen: u64) -> Self {
        Self {
            current_generation: current_gen,
        }
    }

    pub(crate) fn resolve_cursor(&self, cursor: &OccurrenceCursor) -> Result<u64, TxQueryError> {
        if cursor.generation_id < self.current_generation {
            return Err(TxQueryError::ExpiredView);
        }
        Ok(u64::from(cursor.height))
    }
}

#[derive(Clone, Debug)]
#[expect(dead_code, reason = "model state fields")]
pub(crate) struct MockEngineState {
    pub(crate) current_tip_height: u32,
    pub(crate) current_commit_id: u64,
}

impl MockEngineState {
    #[must_use]
    pub(crate) const fn new(extended_height: u32, extended_commit: u64) -> Self {
        Self {
            current_tip_height: extended_height,
            current_commit_id: extended_commit,
        }
    }

    pub(crate) fn query_history_at_view(
        &self,
        view: &ServingView,
        target_height: u32,
    ) -> Result<QueryAnswer, TxQueryError> {
        if target_height > view.epoch.tip_height {
            return Err(TxQueryError::Unavailable(
                TxUnavailableCause::OutsideCoverage {
                    declared_floor_or_tip: view.epoch.tip_height,
                },
            ));
        }
        Ok(QueryAnswer {
            height: view.epoch.tip_height,
            block_hash: view.epoch.tip_hash,
            coverage: view.coverage.clone(),
            payload: u64::from(target_height),
        })
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct LockTracker {
    transition_lock_acquisitions: usize,
    utxo_store_reads: usize,
}

impl LockTracker {
    #[must_use]
    pub(crate) const fn new() -> Self {
        Self {
            transition_lock_acquisitions: 0,
            utxo_store_reads: 0,
        }
    }

    #[must_use]
    pub(crate) const fn transition_lock_acquisitions(&self) -> usize {
        self.transition_lock_acquisitions
    }

    #[must_use]
    pub(crate) const fn utxo_store_reads(&self) -> usize {
        self.utxo_store_reads
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub(crate) struct OutPoint {
    pub(crate) txid: [u8; 32],
    pub(crate) vout: u32,
}

impl OutPoint {
    #[cfg(kani)]
    #[must_use]
    pub(crate) fn arbitrary() -> Self {
        Self {
            txid: kani::any(),
            vout: kani::any(),
        }
    }

    #[cfg(not(kani))]
    #[must_use]
    #[expect(dead_code, reason = "kani harness helper")]
    pub(crate) const fn arbitrary() -> Self {
        Self {
            txid: [0u8; 32],
            vout: 0,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ScriptLiveRow {
    pub(crate) outpoint: OutPoint,
    pub(crate) script_hash: [u8; 32],
    pub(crate) value: u64,
    pub(crate) height: u32,
    pub(crate) coinbase: bool,
}

pub(crate) struct ScriptLiveView<'a> {
    row: ScriptLiveRow,
    _tracker: &'a LockTracker,
}

impl<'a> ScriptLiveView<'a> {
    #[must_use]
    pub(crate) const fn with_row_and_tracker(row: ScriptLiveRow, tracker: &'a LockTracker) -> Self {
        Self {
            row,
            _tracker: tracker,
        }
    }

    #[must_use]
    pub(crate) fn unspent_outputs_for(&self, script_hash: &[u8; 32]) -> Vec<OutPoint> {
        if self.row.script_hash == *script_hash {
            vec![self.row.outpoint]
        } else {
            vec![]
        }
    }
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub(crate) struct LockState {
    pub(crate) transition_lock: bool,
    pub(crate) chain_lock: bool,
    pub(crate) mempool_lock: bool,
}

impl LockState {
    #[must_use]
    pub(crate) const fn any_held(&self) -> bool {
        self.transition_lock || self.chain_lock || self.mempool_lock
    }
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub(crate) enum QueryPhase {
    #[default]
    Idle,
    Captured,
    ResponseReady,
    Serializing,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct QuerySession {
    phase: QueryPhase,
    locks: LockState,
    buffer_ready: bool,
}

impl QuerySession {
    #[must_use]
    pub(crate) const fn new() -> Self {
        Self {
            phase: QueryPhase::Idle,
            locks: LockState {
                transition_lock: false,
                chain_lock: false,
                mempool_lock: false,
            },
            buffer_ready: false,
        }
    }

    pub(crate) fn access_state(&mut self) {
        self.phase = QueryPhase::Captured;
    }

    pub(crate) fn release_state_and_build_buffer(&mut self) {
        self.phase = QueryPhase::ResponseReady;
        self.buffer_ready = true;
        self.locks = LockState::default();
    }

    pub(crate) fn start_serialization(&mut self) -> bool {
        if self.phase == QueryPhase::ResponseReady && self.buffer_ready && !self.locks.any_held() {
            self.phase = QueryPhase::Serializing;
            true
        } else {
            false
        }
    }

    #[must_use]
    pub(crate) const fn holds_chain_lock(&self) -> bool {
        self.locks.chain_lock
    }

    #[must_use]
    pub(crate) const fn holds_transition_lock(&self) -> bool {
        self.locks.transition_lock
    }

    #[must_use]
    pub(crate) const fn holds_mempool_lock(&self) -> bool {
        self.locks.mempool_lock
    }

    pub(crate) fn complete(&mut self) {
        self.phase = QueryPhase::Idle;
        self.buffer_ready = false;
    }
}

#[must_use]
pub(crate) fn execute_mock_query(view: &ServingView, _target_height: u32) -> QueryAnswer {
    QueryAnswer {
        height: view.epoch.tip_height,
        block_hash: view.epoch.tip_hash,
        coverage: view.coverage.clone(),
        payload: 42,
    }
}

#[must_use]
pub(crate) fn capture_test_view(initial_height: u32, initial_commit: u64) -> ServingView {
    let epoch = AppliedEpoch {
        chain_id: Network::Mainnet,
        tip_hash: BlockHash([1u8; 32]),
        tip_height: initial_height,
        commit_id: initial_commit,
    };
    ServingView::new(
        epoch,
        1,
        CapabilityCoverage {
            txindex: Some(initial_height),
            scriptindex: Some(initial_height),
            blockfilterindex: Some(initial_height),
        },
    )
}

#[must_use]
pub(crate) fn capture_view_with_coverage(coverage_height: u32) -> ServingView {
    let epoch = AppliedEpoch {
        chain_id: Network::Mainnet,
        tip_hash: BlockHash([0u8; 32]),
        tip_height: coverage_height,
        commit_id: 1,
    };
    ServingView::new(
        epoch,
        1,
        CapabilityCoverage {
            txindex: Some(coverage_height),
            scriptindex: Some(coverage_height),
            blockfilterindex: Some(coverage_height),
        },
    )
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub(crate) struct ViewRecord {
    pub(crate) captured: bool,
    pub(crate) view_epoch_height: u32,
    pub(crate) view_epoch_commit: u64,
    pub(crate) view_gen: u64,
    pub(crate) view_coverage: u32,
    pub(crate) status: ViewStatus,
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub(crate) enum QueryResult {
    #[default]
    None,
    AnswerOk,
    Unavailable,
    ExpiredView,
    Retry,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct State {
    pub(crate) tip_height: u32,
    pub(crate) tip_commit: u64,
    pub(crate) current_gen: u64,
    pub(crate) retired_gens: [bool; 4],
    pub(crate) coverage_height: u32,
    pub(crate) views: [ViewRecord; 3],
    pub(crate) query_phase: QueryPhase,
    pub(crate) query_view_id: usize,
    pub(crate) query_target_height: u32,
    pub(crate) query_is_tip_promised: bool,
    pub(crate) query_is_script_live: bool,
    pub(crate) query_result: QueryResult,
    pub(crate) query_locks_held: LockState,
}

#[must_use]
pub(crate) fn is_gen_retired(retired_gens: &[bool; 4], generation: u64) -> bool {
    if let Ok(idx) = usize::try_from(generation) {
        idx > 0 && idx < retired_gens.len() && retired_gens[idx]
    } else {
        false
    }
}

impl State {
    #[must_use]
    pub(crate) const fn init() -> Self {
        Self {
            tip_height: 0,
            tip_commit: 0,
            current_gen: 1,
            retired_gens: [false; 4],
            coverage_height: 0,
            views: [ViewRecord {
                captured: false,
                view_epoch_height: 0,
                view_epoch_commit: 0,
                view_gen: 1,
                view_coverage: 0,
                status: ViewStatus::None,
            }; 3],
            query_phase: QueryPhase::Idle,
            query_view_id: 1,
            query_target_height: 0,
            query_is_tip_promised: false,
            query_is_script_live: false,
            query_result: QueryResult::None,
            query_locks_held: LockState {
                transition_lock: false,
                chain_lock: false,
                mempool_lock: false,
            },
        }
    }

    #[must_use]
    pub(crate) fn is_generation_retired(&self, generation: u64) -> bool {
        is_gen_retired(&self.retired_gens, generation)
    }

    #[must_use]
    pub(crate) fn is_view_retired(&self, view_id: usize) -> bool {
        if view_id > 0 && view_id <= MAX_VIEWS {
            let v = self.views[view_id];
            v.status == ViewStatus::Expired || self.is_generation_retired(v.view_gen)
        } else {
            false
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Action {
    ExtendChain,
    AdvanceCoverage,
    DeepReorg,
    CaptureView {
        view_id: usize,
        is_script_live: bool,
        is_tip: bool,
        target_height: u32,
    },
    AccessState,
    StartSerialization,
    FinishQuery,
    Stutter,
}

#[must_use]
pub(crate) fn step(state: &State, action: &Action) -> State {
    let mut next = state.clone();
    match action {
        Action::ExtendChain => {
            if state.tip_height < MAX_HEIGHT {
                next.tip_height += 1;
                next.tip_commit += 1;
            }
        }
        Action::AdvanceCoverage => {
            if state.coverage_height < state.tip_height {
                next.coverage_height += 1;
            }
        }
        Action::DeepReorg => {
            if state.current_gen < MAX_GENERATIONS {
                let gen_idx = usize::try_from(state.current_gen).unwrap_or(0);
                if gen_idx < next.retired_gens.len() {
                    next.retired_gens[gen_idx] = true;
                }
                next.current_gen += 1;
                let retired_gens = next.retired_gens;
                for v in &mut next.views[1..=MAX_VIEWS] {
                    let is_retired = v.view_gen == state.current_gen
                        || is_gen_retired(&retired_gens, v.view_gen);
                    if v.captured && is_retired {
                        v.status = ViewStatus::Expired;
                    }
                }
            }
        }
        Action::CaptureView {
            view_id,
            is_script_live,
            is_tip,
            target_height,
        } => {
            if state.query_phase == QueryPhase::Idle
                && *view_id >= 1
                && *view_id <= MAX_VIEWS
                && *target_height <= MAX_HEIGHT
            {
                next.views[*view_id] = ViewRecord {
                    captured: true,
                    view_epoch_height: state.tip_height,
                    view_epoch_commit: state.tip_commit,
                    view_gen: state.current_gen,
                    view_coverage: state.coverage_height,
                    status: ViewStatus::Active,
                };
                next.query_phase = QueryPhase::Captured;
                next.query_view_id = *view_id;
                next.query_target_height = *target_height;
                next.query_is_tip_promised = *is_tip;
                next.query_is_script_live = *is_script_live;
                next.query_result = QueryResult::None;
                next.query_locks_held = LockState::default();
            }
        }
        Action::AccessState => {
            if state.query_phase == QueryPhase::Captured {
                let v = state.views[state.query_view_id];
                if state.is_view_retired(state.query_view_id) {
                    next.query_result = QueryResult::ExpiredView;
                    next.query_locks_held = LockState::default();
                    next.query_phase = QueryPhase::ResponseReady;
                } else if state.query_is_tip_promised && v.view_epoch_commit != state.tip_commit {
                    next.query_result = QueryResult::Retry;
                    next.query_locks_held = LockState::default();
                    next.query_phase = QueryPhase::ResponseReady;
                } else if state.query_target_height > v.view_coverage {
                    next.query_result = QueryResult::Unavailable;
                    next.query_locks_held = LockState::default();
                    next.query_phase = QueryPhase::ResponseReady;
                } else {
                    next.query_result = QueryResult::AnswerOk;
                    next.query_locks_held = LockState::default();
                    next.query_phase = QueryPhase::ResponseReady;
                }
            }
        }
        Action::StartSerialization => {
            if state.query_phase == QueryPhase::ResponseReady && !state.query_locks_held.any_held()
            {
                next.query_phase = QueryPhase::Serializing;
            }
        }
        Action::FinishQuery => {
            if state.query_phase == QueryPhase::Serializing {
                next.query_phase = QueryPhase::Idle;
                next.query_result = QueryResult::None;
            }
        }
        Action::Stutter => {}
    }
    next
}

#[must_use]
pub(crate) fn step_mutant_removed_coverage_guard(state: &State, action: &Action) -> State {
    let mut next = state.clone();
    match action {
        Action::AccessState => {
            if state.query_phase == QueryPhase::Captured {
                let v = state.views[state.query_view_id];
                if state.is_view_retired(state.query_view_id) {
                    next.query_result = QueryResult::ExpiredView;
                    next.query_locks_held = LockState::default();
                    next.query_phase = QueryPhase::ResponseReady;
                } else if state.query_is_tip_promised && v.view_epoch_commit != state.tip_commit {
                    next.query_result = QueryResult::Retry;
                    next.query_locks_held = LockState::default();
                    next.query_phase = QueryPhase::ResponseReady;
                } else {
                    next.query_result = QueryResult::AnswerOk;
                    next.query_locks_held = LockState::default();
                    next.query_phase = QueryPhase::ResponseReady;
                }
            }
        }
        _ => return step(state, action),
    }
    next
}

// QRY-03
#[must_use]
pub(crate) const fn safety_history_query_never_retries(state: &State) -> bool {
    if matches!(state.query_result, QueryResult::Retry) {
        state.query_is_tip_promised
    } else {
        true
    }
}

// QRY-05
#[must_use]
pub(crate) const fn safety_coverage_unavailable(state: &State) -> bool {
    if matches!(state.query_result, QueryResult::AnswerOk) {
        state.query_target_height <= state.views[state.query_view_id].view_coverage
    } else {
        true
    }
}

// QRY-06
#[must_use]
pub(crate) fn safety_expired_view_from_retirement(state: &State) -> bool {
    if matches!(state.query_result, QueryResult::ExpiredView) {
        state.is_view_retired(state.query_view_id)
    } else {
        true
    }
}

// QRY-06
#[must_use]
pub(crate) fn safety_access_from_retired_never_answers_ok(state: &State) -> bool {
    if matches!(state.query_phase, QueryPhase::Captured)
        && state.is_view_retired(state.query_view_id)
    {
        !matches!(state.query_result, QueryResult::AnswerOk)
    } else {
        true
    }
}

// PRJ-11
#[must_use]
pub(crate) const fn safety_script_live_lock_free(state: &State) -> bool {
    if state.query_is_script_live {
        !state.query_locks_held.transition_lock
    } else {
        true
    }
}

// QRY-08
#[must_use]
pub(crate) const fn safety_serialization_no_locks(state: &State) -> bool {
    if matches!(state.query_phase, QueryPhase::Serializing) {
        !state.query_locks_held.any_held()
    } else {
        true
    }
}

#[must_use]
pub(crate) fn safety(state: &State) -> bool {
    safety_history_query_never_retries(state)
        && safety_coverage_unavailable(state)
        && safety_expired_view_from_retirement(state)
        && safety_access_from_retired_never_answers_ok(state)
        && safety_script_live_lock_free(state)
        && safety_serialization_no_locks(state)
}

// QRY-01, QRY-04
#[cfg(kani)]
#[kani::proof]
#[kani::unwind(34)]
pub fn check_serving_view_capture_epoch() {
    let tip_height: u32 = kani::any();
    let tip_hash: [u8; 32] = kani::any();
    let commit_id: u64 = kani::any();
    kani::assume(tip_height <= 1_000_000);

    let epoch = AppliedEpoch {
        chain_id: Network::Mainnet,
        tip_hash: BlockHash(tip_hash),
        tip_height,
        commit_id,
    };
    let coverage = CapabilityCoverage::arbitrary();
    let generation_id: u64 = kani::any();

    let view = ServingView::new(epoch, generation_id, coverage.clone());
    let answer = execute_mock_query(&view, 42);

    assert_eq!(answer.height, tip_height);
    assert_eq!(answer.block_hash, BlockHash(tip_hash));
    assert_eq!(answer.coverage, coverage);
}

// QRY-03
#[cfg(kani)]
#[kani::proof]
#[kani::unwind(4)]
pub fn check_history_query_immutable_under_chain_extension() {
    let initial_height: u32 = kani::any();
    let initial_commit: u64 = kani::any();
    kani::assume(initial_height < u32::MAX);
    kani::assume(initial_commit < u64::MAX);

    let view = capture_test_view(initial_height, initial_commit);

    let extended_height = initial_height + 1;
    let extended_commit = initial_commit + 1;
    let engine_state = MockEngineState::new(extended_height, extended_commit);

    let result = engine_state.query_history_at_view(&view, initial_height);

    assert!(!matches!(result, Err(TxQueryError::Retry(_))));
    if let Ok(answer) = result {
        assert_eq!(answer.height, initial_height);
    }
}

// QRY-05
#[cfg(kani)]
#[kani::proof]
#[kani::unwind(4)]
pub fn check_query_outside_coverage_unavailable() {
    let coverage_height: u32 = kani::any();
    let target_height: u32 = kani::any();
    kani::assume(coverage_height < 1_000_000);
    kani::assume(target_height > coverage_height);

    let view = capture_view_with_coverage(coverage_height);
    let result = view.query_tx_at_height(target_height);

    match result {
        Err(TxQueryError::Unavailable(cause)) => {
            assert_eq!(cause.declared_floor_or_tip(), coverage_height);
        }
        Ok(_) => panic!("QRY-05 VIOLATION: query outside coverage returned Ok!"),
        Err(other) => panic!("Unexpected error: {other:?}"),
    }
}

// QRY-06
#[cfg(kani)]
#[kani::proof]
#[kani::unwind(4)]
pub fn check_retired_view_occurrence_cursor_expired() {
    let captured_gen: u64 = kani::any();
    let current_gen: u64 = kani::any();
    kani::assume(current_gen > captured_gen);

    let cursor = OccurrenceCursor {
        generation_id: captured_gen,
        height: 100,
        tx_pos: 2,
    };

    let engine = MockIndexEngine::with_generation(current_gen);
    let result = engine.resolve_cursor(&cursor);

    assert!(matches!(result, Err(TxQueryError::ExpiredView)));
}

// PRJ-11
#[cfg(kani)]
#[kani::proof]
#[kani::unwind(34)]
pub fn check_script_live_zero_transition_lock() {
    let lock_tracker = LockTracker::new();
    let script_hash: [u8; 32] = kani::any();

    let row = ScriptLiveRow {
        outpoint: OutPoint::arbitrary(),
        script_hash,
        value: kani::any(),
        height: kani::any(),
        coinbase: kani::any(),
    };

    let view = ScriptLiveView::with_row_and_tracker(row, &lock_tracker);
    let _ = view.unspent_outputs_for(&script_hash);

    assert_eq!(lock_tracker.transition_lock_acquisitions(), 0);
    assert_eq!(lock_tracker.utxo_store_reads(), 0);
}

// QRY-08
#[cfg(kani)]
#[kani::proof]
#[kani::unwind(4)]
pub fn check_serialization_no_locks_held() {
    let mut session = QuerySession::new();

    session.access_state();
    session.release_state_and_build_buffer();

    let in_serialization = session.start_serialization();
    assert!(in_serialization);

    assert!(!session.holds_chain_lock());
    assert!(!session.holds_transition_lock());
    assert!(!session.holds_mempool_lock());

    session.complete();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashSet, VecDeque};

    #[test]
    fn test_serving_view_bfs_exhaustive_safety() {
        let init_state = State::init();
        assert!(safety(&init_state));

        let mut visited: HashSet<State> = HashSet::new();
        let mut queue: VecDeque<State> = VecDeque::new();

        visited.insert(init_state.clone());
        queue.push_back(init_state);

        let mut actions = vec![
            Action::ExtendChain,
            Action::AdvanceCoverage,
            Action::DeepReorg,
            Action::AccessState,
            Action::StartSerialization,
            Action::FinishQuery,
            Action::Stutter,
        ];
        let flags = [(false, false), (false, true), (true, false), (true, true)];
        for view_id in 1..=MAX_VIEWS {
            for (is_script_live, is_tip) in flags {
                for target_height in 0..=MAX_HEIGHT {
                    actions.push(Action::CaptureView {
                        view_id,
                        is_script_live,
                        is_tip,
                        target_height,
                    });
                }
            }
        }

        while let Some(current) = queue.pop_front() {
            for action in &actions {
                let next = step(&current, action);
                assert!(safety(&next));
                if visited.insert(next.clone()) {
                    queue.push_back(next);
                }
            }
        }

        assert_eq!(visited.len(), 30684);
    }

    #[test]
    fn test_serving_view_negative_control_removed_coverage_guard() {
        let mut state = State::init();
        state = step(
            &state,
            &Action::CaptureView {
                view_id: 1,
                is_script_live: false,
                is_tip: false,
                target_height: 2,
            },
        );
        assert_eq!(state.query_phase, QueryPhase::Captured);
        assert_eq!(state.views[1].view_coverage, 0);

        let safe_next = step(&state, &Action::AccessState);
        assert_eq!(safe_next.query_result, QueryResult::Unavailable);
        assert!(safety_coverage_unavailable(&safe_next));

        let mutant_next = step_mutant_removed_coverage_guard(&state, &Action::AccessState);
        assert_eq!(mutant_next.query_result, QueryResult::AnswerOk);
        assert!(!safety_coverage_unavailable(&mutant_next));
        assert!(!safety(&mutant_next));
    }

    #[test]
    fn test_serving_view_capture_epoch() {
        let epoch = AppliedEpoch {
            chain_id: Network::Mainnet,
            tip_hash: BlockHash([9u8; 32]),
            tip_height: 50,
            commit_id: 10,
        };
        let coverage = CapabilityCoverage {
            txindex: Some(50),
            scriptindex: Some(40),
            blockfilterindex: Some(50),
        };
        let view = ServingView::new(epoch, 1, coverage.clone());
        let answer = execute_mock_query(&view, 25);
        assert_eq!(answer.height, 50);
        assert_eq!(answer.block_hash, BlockHash([9u8; 32]));
        assert_eq!(answer.coverage, coverage);
    }

    #[test]
    fn test_history_query_immutable_under_chain_extension() {
        let view = capture_test_view(100, 5);
        let extended_engine = MockEngineState::new(101, 6);
        let result = extended_engine.query_history_at_view(&view, 100);
        assert!(result.is_ok());
        let Ok(answer) = result else {
            panic!("query failed");
        };
        assert_eq!(answer.height, 100);
    }

    #[test]
    fn test_query_outside_coverage_returns_unavailable() {
        let view = capture_view_with_coverage(10);
        let result = view.query_tx_at_height(15);
        match result {
            Err(TxQueryError::Unavailable(cause)) => {
                assert_eq!(cause.declared_floor_or_tip(), 10);
            }
            _ => panic!("Expected unavailable"),
        }
    }

    #[test]
    fn test_retired_view_occurrence_cursor_expired() {
        let cursor = OccurrenceCursor {
            generation_id: 1,
            height: 10,
            tx_pos: 0,
        };
        let engine = MockIndexEngine::with_generation(2);
        assert!(matches!(
            engine.resolve_cursor(&cursor),
            Err(TxQueryError::ExpiredView)
        ));
    }

    #[test]
    fn test_script_live_zero_transition_lock() {
        let tracker = LockTracker::new();
        let script_hash = [7u8; 32];
        let row = ScriptLiveRow {
            outpoint: OutPoint {
                txid: [3u8; 32],
                vout: 1,
            },
            script_hash,
            value: 50_000,
            height: 100,
            coinbase: false,
        };
        let view = ScriptLiveView::with_row_and_tracker(row, &tracker);
        let outputs = view.unspent_outputs_for(&script_hash);
        assert_eq!(outputs.len(), 1);
        assert_eq!(tracker.transition_lock_acquisitions(), 0);
        assert_eq!(tracker.utxo_store_reads(), 0);
    }

    #[test]
    fn test_serialization_no_locks_held() {
        let mut session = QuerySession::new();
        session.access_state();
        session.release_state_and_build_buffer();
        assert!(session.start_serialization());
        assert!(!session.holds_chain_lock());
        assert!(!session.holds_transition_lock());
        assert!(!session.holds_mempool_lock());
        session.complete();
    }
}
