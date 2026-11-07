//! Executable reference model and Kani verification harnesses for SnapshotBootstrap lifecycle.

pub(crate) const BASE_HEIGHT: u32 = 2;
pub(crate) const MAX_HEIGHT: u32 = 4;

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub(crate) enum HistoricalBodiesMode {
    #[default]
    Pruned,
    Retained,
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
    pub(crate) const fn arbitrary() -> Self {
        Self {
            txid: [0u8; 32],
            vout: 0,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SnapshotCoin {
    pub(crate) outpoint: OutPoint,
    pub(crate) amount: u64,
    pub(crate) height: u32,
}

impl SnapshotCoin {
    #[cfg(kani)]
    #[must_use]
    pub(crate) fn arbitrary() -> Self {
        Self {
            outpoint: OutPoint::arbitrary(),
            amount: kani::any(),
            height: kani::any(),
        }
    }

    #[cfg(not(kani))]
    #[must_use]
    pub(crate) const fn arbitrary() -> Self {
        Self {
            outpoint: OutPoint::arbitrary(),
            amount: 50_000,
            height: 100,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct MockUnpublishedCoinSink {
    count: usize,
}

impl MockUnpublishedCoinSink {
    #[must_use]
    pub(crate) const fn new() -> Self {
        Self { count: 0 }
    }

    pub(crate) fn observe_coin(&mut self, _coin: &SnapshotCoin) {
        self.count += 1;
    }

    #[must_use]
    pub(crate) const fn count(&self) -> usize {
        self.count
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct MockUnpublishedScriptLiveSink {
    count: usize,
}

impl MockUnpublishedScriptLiveSink {
    #[must_use]
    pub(crate) const fn new() -> Self {
        Self { count: 0 }
    }

    pub(crate) fn observe_coin(&mut self, _coin: &SnapshotCoin) {
        self.count += 1;
    }

    #[must_use]
    pub(crate) const fn count(&self) -> usize {
        self.count
    }
}

pub(crate) struct PairObserver<'a> {
    coin_sink: &'a mut MockUnpublishedCoinSink,
    script_sink: &'a mut MockUnpublishedScriptLiveSink,
    stream_passes: usize,
}

impl<'a> PairObserver<'a> {
    #[must_use]
    pub(crate) fn new(
        coin_sink: &'a mut MockUnpublishedCoinSink,
        script_sink: &'a mut MockUnpublishedScriptLiveSink,
    ) -> Self {
        Self {
            coin_sink,
            script_sink,
            stream_passes: 1,
        }
    }

    pub(crate) fn observe_coin(&mut self, coin: &SnapshotCoin) {
        self.coin_sink.observe_coin(coin);
        self.script_sink.observe_coin(coin);
    }

    #[must_use]
    pub(crate) const fn stream_passes(&self) -> usize {
        self.stream_passes
    }
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum SnapshotBootstrapError {
    #[error("manifest anchor mismatch")]
    MismatchedAnchor,
    #[error("index commitment mismatch")]
    MismatchedIndex,
}

#[derive(Clone, Debug)]
pub(crate) struct SnapshotBootstrapState {
    manifest_hash: [u8; 32],
    compiled_anchor: [u8; 32],
    streamed: bool,
    coin_store_published: bool,
    script_live_published: bool,
    discarded: bool,
}

impl SnapshotBootstrapState {
    #[must_use]
    pub(crate) const fn new(manifest_hash: [u8; 32], compiled_anchor: [u8; 32]) -> Self {
        Self {
            manifest_hash,
            compiled_anchor,
            streamed: false,
            coin_store_published: false,
            script_live_published: false,
            discarded: false,
        }
    }

    pub(crate) fn stream_unpublished_data(&mut self) {
        self.streamed = true;
        self.coin_store_published = false;
        self.script_live_published = false;
    }

    #[must_use]
    pub(crate) const fn is_coin_store_published(&self) -> bool {
        self.coin_store_published
    }

    #[must_use]
    pub(crate) const fn is_script_live_published(&self) -> bool {
        self.script_live_published
    }

    #[must_use]
    pub(crate) const fn unpublished_data_discarded(&self) -> bool {
        self.discarded
    }

    pub(crate) fn verify_and_activate(&mut self) -> Result<(), SnapshotBootstrapError> {
        if self.manifest_hash == self.compiled_anchor {
            self.coin_store_published = true;
            self.script_live_published = true;
            Ok(())
        } else {
            self.coin_store_published = false;
            self.script_live_published = false;
            self.discarded = true;
            Err(SnapshotBootstrapError::MismatchedAnchor)
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct IndexArtifactBootstrap {
    manifest_index_hash: [u8; 32],
}

impl IndexArtifactBootstrap {
    #[must_use]
    pub(crate) const fn new(manifest_index_hash: [u8; 32]) -> Self {
        Self {
            manifest_index_hash,
        }
    }

    pub(crate) fn verify_and_attach(
        &mut self,
        compiled_index_hash: [u8; 32],
    ) -> Result<AttachedIndexGeneration, SnapshotBootstrapError> {
        if self.manifest_index_hash == compiled_index_hash {
            Ok(AttachedIndexGeneration {
                attached: true,
                restored_rows: 0,
            })
        } else {
            Err(SnapshotBootstrapError::MismatchedIndex)
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AttachedIndexGeneration {
    attached: bool,
    restored_rows: usize,
}

impl AttachedIndexGeneration {
    #[must_use]
    pub(crate) const fn is_attached(&self) -> bool {
        self.attached
    }

    #[must_use]
    pub(crate) const fn restore_row_count(&self) -> usize {
        self.restored_rows
    }
}

#[derive(Clone, Debug)]
pub(crate) struct NodeBootstrapController {
    utxo_valid: bool,
    index_valid: bool,
}

impl NodeBootstrapController {
    #[must_use]
    pub(crate) const fn new(utxo_valid: bool, index_valid: bool) -> Self {
        Self {
            utxo_valid,
            index_valid,
        }
    }

    #[must_use]
    pub(crate) const fn execute(&self) -> BootstrapOutcome {
        if !self.utxo_valid {
            BootstrapOutcome {
                chainstate_closed: true,
                chainstate_active: false,
                index_invalidated: false,
                index_attached: false,
            }
        } else {
            BootstrapOutcome {
                chainstate_closed: false,
                chainstate_active: true,
                index_invalidated: !self.index_valid,
                index_attached: self.index_valid,
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BootstrapOutcome {
    pub(crate) chainstate_closed: bool,
    pub(crate) chainstate_active: bool,
    pub(crate) index_invalidated: bool,
    pub(crate) index_attached: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct NodeProgressStatus {
    active_chain: u32,
    historical_validation: u32,
    projection_coverage: u32,
}

impl NodeProgressStatus {
    #[must_use]
    pub(crate) const fn from_bootstrap(base_height: u32) -> Self {
        Self {
            active_chain: base_height,
            historical_validation: 0,
            projection_coverage: base_height,
        }
    }

    #[must_use]
    pub(crate) const fn active_chain_height(&self) -> u32 {
        self.active_chain
    }

    #[must_use]
    pub(crate) const fn historical_validation_height(&self) -> u32 {
        self.historical_validation
    }

    #[must_use]
    pub(crate) const fn projection_coverage_height(&self) -> u32 {
        self.projection_coverage
    }

    pub(crate) fn connect_block_above_tip(&mut self) {
        self.active_chain += 1;
    }

    pub(crate) fn step_historical_validation(&mut self, step: u32) {
        self.historical_validation += step;
    }

    pub(crate) fn advance_projection_coverage(&mut self, step: u32) {
        self.projection_coverage += step;
    }
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum StorageError {
    #[error("historical body unavailable")]
    HistoricalBodyUnavailable,
}

#[derive(Clone, Debug)]
pub(crate) struct MockStorage {
    base_height: u32,
    mode: HistoricalBodiesMode,
}

impl MockStorage {
    #[must_use]
    pub(crate) const fn new(base_height: u32, mode: HistoricalBodiesMode) -> Self {
        Self { base_height, mode }
    }

    pub(crate) fn load_raw_block_body(&self, height: u32) -> Result<Vec<u8>, StorageError> {
        if height <= self.base_height {
            match self.mode {
                HistoricalBodiesMode::Retained => Ok(vec![0xaa]),
                HistoricalBodiesMode::Pruned => Err(StorageError::HistoricalBodyUnavailable),
            }
        } else {
            Ok(vec![0xbb])
        }
    }
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub(crate) enum BootstrapPhase {
    #[default]
    Init,
    Streaming,
    Verifying,
    Ready,
    Failed,
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub(crate) enum BodyQueryResult {
    #[default]
    None,
    BodyFound,
    BodyUnavailable,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct State {
    pub(crate) bootstrap_phase: BootstrapPhase,
    pub(crate) unpublished_streamed: bool,
    pub(crate) coins_published: bool,
    pub(crate) script_live_published: bool,
    pub(crate) utxo_verified: bool,
    pub(crate) index_verified: bool,
    pub(crate) index_attached: bool,
    pub(crate) index_invalidated: bool,
    pub(crate) chainstate_closed: bool,
    pub(crate) unpublished_discarded: bool,
    pub(crate) active_tip_height: u32,
    pub(crate) historical_val_height: u32,
    pub(crate) projection_coverage: u32,
    pub(crate) body_query_height: u32,
    pub(crate) body_query_result: BodyQueryResult,
}

impl State {
    #[must_use]
    pub(crate) const fn init() -> Self {
        Self {
            bootstrap_phase: BootstrapPhase::Init,
            unpublished_streamed: false,
            coins_published: false,
            script_live_published: false,
            utxo_verified: false,
            index_verified: false,
            index_attached: false,
            index_invalidated: false,
            chainstate_closed: false,
            unpublished_discarded: false,
            active_tip_height: 0,
            historical_val_height: 0,
            projection_coverage: 0,
            body_query_height: 0,
            body_query_result: BodyQueryResult::None,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Action {
    StreamSnapshot,
    VerifyCommitments { utxo_ok: bool, index_ok: bool },
    PublishValidSnapshot,
    RejectInvalidUtxo,
    AdvanceActiveChain,
    AdvanceHistoricalValidation,
    AdvanceProjectionCoverage,
    QueryHistoricalBody { height: u32 },
    Stutter,
}

fn apply_publish_valid(next: &mut State) {
    next.coins_published = true;
    next.script_live_published = true;
    if next.index_verified {
        next.index_attached = true;
        next.index_invalidated = false;
        next.projection_coverage = BASE_HEIGHT;
    } else {
        next.index_attached = false;
        next.index_invalidated = true;
        next.projection_coverage = 0;
    }
    next.active_tip_height = BASE_HEIGHT;
    next.bootstrap_phase = BootstrapPhase::Ready;
}

fn apply_query_body(next: &mut State, height: u32, mode: HistoricalBodiesMode) {
    next.body_query_height = height;
    if height <= BASE_HEIGHT {
        match mode {
            HistoricalBodiesMode::Retained => next.body_query_result = BodyQueryResult::BodyFound,
            HistoricalBodiesMode::Pruned => {
                next.body_query_result = BodyQueryResult::BodyUnavailable;
            }
        }
    } else {
        next.body_query_result = BodyQueryResult::BodyFound;
    }
}

#[must_use]
pub(crate) fn step(state: &State, action: &Action, mode: HistoricalBodiesMode) -> State {
    let mut next = state.clone();
    match action {
        Action::StreamSnapshot => {
            if state.bootstrap_phase == BootstrapPhase::Init {
                next.unpublished_streamed = true;
                next.coins_published = false;
                next.script_live_published = false;
                next.bootstrap_phase = BootstrapPhase::Streaming;
            }
        }
        Action::VerifyCommitments { utxo_ok, index_ok } => {
            if state.bootstrap_phase == BootstrapPhase::Streaming {
                next.utxo_verified = *utxo_ok;
                next.index_verified = *index_ok;
                next.bootstrap_phase = BootstrapPhase::Verifying;
            }
        }
        Action::PublishValidSnapshot => {
            if state.bootstrap_phase == BootstrapPhase::Verifying && state.utxo_verified {
                apply_publish_valid(&mut next);
            }
        }
        Action::RejectInvalidUtxo => {
            if state.bootstrap_phase == BootstrapPhase::Verifying && !state.utxo_verified {
                next.unpublished_discarded = true;
                next.chainstate_closed = true;
                next.coins_published = false;
                next.script_live_published = false;
                next.index_attached = false;
                next.index_invalidated = false;
                next.bootstrap_phase = BootstrapPhase::Failed;
            }
        }
        Action::AdvanceActiveChain => {
            if state.bootstrap_phase == BootstrapPhase::Ready
                && !state.chainstate_closed
                && state.active_tip_height < MAX_HEIGHT
            {
                next.active_tip_height += 1;
            }
        }
        Action::AdvanceHistoricalValidation => {
            if state.bootstrap_phase == BootstrapPhase::Ready
                && state.historical_val_height < BASE_HEIGHT
            {
                next.historical_val_height += 1;
            }
        }
        Action::AdvanceProjectionCoverage => {
            if state.bootstrap_phase == BootstrapPhase::Ready
                && state.index_attached
                && state.projection_coverage < state.active_tip_height
            {
                next.projection_coverage += 1;
            }
        }
        Action::QueryHistoricalBody { height } => {
            if state.bootstrap_phase == BootstrapPhase::Ready {
                apply_query_body(&mut next, *height, mode);
            }
        }
        Action::Stutter => {}
    }
    next
}

#[must_use]
pub(crate) fn step_mutant_removed_utxo_verification_guard(
    state: &State,
    action: &Action,
    mode: HistoricalBodiesMode,
) -> State {
    let mut next = state.clone();
    match action {
        Action::PublishValidSnapshot => {
            if state.bootstrap_phase == BootstrapPhase::Verifying {
                apply_publish_valid(&mut next);
            }
        }
        _ => return step(state, action, mode),
    }
    next
}

// SNP-07
#[must_use]
pub(crate) const fn safety_publication_requires_utxo_verification(state: &State) -> bool {
    if state.coins_published || state.script_live_published {
        state.utxo_verified
    } else {
        true
    }
}

// SNP-07, SNP-10
#[must_use]
pub(crate) const fn safety_invalid_utxo_never_published(state: &State) -> bool {
    let in_untrusted_phase = matches!(
        state.bootstrap_phase,
        BootstrapPhase::Verifying | BootstrapPhase::Failed
    );
    if !state.utxo_verified && in_untrusted_phase {
        !state.coins_published && !state.script_live_published
    } else {
        true
    }
}

// SNP-05, SNP-04
#[must_use]
pub(crate) const fn safety_index_attach_requires_verification(state: &State) -> bool {
    if state.index_attached {
        state.index_verified
    } else {
        true
    }
}

// SNP-10
#[must_use]
pub(crate) const fn safety_index_failure_isolated(state: &State) -> bool {
    let is_ready = matches!(state.bootstrap_phase, BootstrapPhase::Ready);
    if state.utxo_verified && !state.index_verified && is_ready {
        !state.chainstate_closed && state.index_invalidated && !state.index_attached
    } else {
        true
    }
}

// SNP-10
#[must_use]
pub(crate) const fn safety_invalid_utxo_closes_chainstate(state: &State) -> bool {
    if matches!(state.bootstrap_phase, BootstrapPhase::Failed) {
        state.chainstate_closed
    } else {
        true
    }
}

// SNP-08, SNP-11
#[must_use]
pub(crate) const fn safety_historical_body_explicit(
    state: &State,
    mode: HistoricalBodiesMode,
) -> bool {
    let has_result = !matches!(state.body_query_result, BodyQueryResult::None);
    if matches!(mode, HistoricalBodiesMode::Pruned)
        && state.body_query_height <= BASE_HEIGHT
        && has_result
    {
        matches!(state.body_query_result, BodyQueryResult::BodyUnavailable)
    } else {
        true
    }
}

// SNP-09
#[must_use]
pub(crate) const fn safety_three_positions_bounded(state: &State) -> bool {
    state.active_tip_height <= MAX_HEIGHT
        && state.historical_val_height <= BASE_HEIGHT
        && state.projection_coverage <= MAX_HEIGHT
}

#[must_use]
pub(crate) fn safety(state: &State, mode: HistoricalBodiesMode) -> bool {
    safety_publication_requires_utxo_verification(state)
        && safety_invalid_utxo_never_published(state)
        && safety_index_attach_requires_verification(state)
        && safety_index_failure_isolated(state)
        && safety_invalid_utxo_closes_chainstate(state)
        && safety_historical_body_explicit(state, mode)
        && safety_three_positions_bounded(state)
}

// SNP-06
#[cfg(kani)]
#[kani::proof]
#[kani::unwind(6)]
pub fn check_streaming_coins_and_script_live_single_pass() {
    let num_records: usize = kani::any();
    kani::assume(num_records <= 4);

    let mut coin_sink = MockUnpublishedCoinSink::new();
    let mut script_sink = MockUnpublishedScriptLiveSink::new();
    {
        let mut pair_observer = PairObserver::new(&mut coin_sink, &mut script_sink);
        for _ in 0..num_records {
            let coin = SnapshotCoin::arbitrary();
            pair_observer.observe_coin(&coin);
        }
        assert_eq!(pair_observer.stream_passes(), 1);
    }
    assert_eq!(coin_sink.count(), num_records);
    assert_eq!(script_sink.count(), num_records);
}

// SNP-07
#[cfg(kani)]
#[kani::proof]
#[kani::unwind(34)]
pub fn check_no_publish_before_utxo_verification() {
    let manifest_hash: [u8; 32] = kani::any();
    let compiled_anchor: [u8; 32] = kani::any();
    let is_valid = manifest_hash == compiled_anchor;

    let mut bootstrap = SnapshotBootstrapState::new(manifest_hash, compiled_anchor);
    bootstrap.stream_unpublished_data();

    assert!(!bootstrap.is_coin_store_published());
    assert!(!bootstrap.is_script_live_published());

    let activation_result = bootstrap.verify_and_activate();

    if is_valid {
        assert!(activation_result.is_ok());
        assert!(bootstrap.is_coin_store_published());
        assert!(bootstrap.is_script_live_published());
    } else {
        assert!(activation_result.is_err());
        assert!(!bootstrap.is_coin_store_published());
        assert!(!bootstrap.is_script_live_published());
        assert!(bootstrap.unpublished_data_discarded());
    }
}

// SNP-04, SNP-05
#[cfg(kani)]
#[kani::proof]
#[kani::unwind(34)]
pub fn check_index_generation_attach_requires_verified_commitment() {
    let manifest_index_hash: [u8; 32] = kani::any();
    let compiled_index_hash: [u8; 32] = kani::any();
    let matches_compiled = manifest_index_hash == compiled_index_hash;

    let mut index_bootstrap = IndexArtifactBootstrap::new(manifest_index_hash);
    let res = index_bootstrap.verify_and_attach(compiled_index_hash);

    if matches_compiled {
        assert!(res.is_ok());
        let Ok(attached_generation) = res else {
            panic!("attachment succeeds on verified commitment");
        };
        assert!(attached_generation.is_attached());
        assert_eq!(attached_generation.restore_row_count(), 0);
    } else {
        assert!(res.is_err());
    }
}

// SNP-10
#[cfg(kani)]
#[kani::proof]
#[kani::unwind(4)]
pub fn check_index_failure_isolated_from_chainstate() {
    let utxo_valid: bool = kani::any();
    let index_valid: bool = kani::any();

    let node_bootstrap = NodeBootstrapController::new(utxo_valid, index_valid);
    let outcome = node_bootstrap.execute();

    if !utxo_valid {
        assert!(outcome.chainstate_closed);
        assert!(!outcome.chainstate_active);
    } else {
        assert!(!outcome.chainstate_closed);
        assert!(outcome.chainstate_active);

        if !index_valid {
            assert!(outcome.index_invalidated);
            assert!(!outcome.index_attached);
        } else {
            assert!(!outcome.index_invalidated);
            assert!(outcome.index_attached);
        }
    }
}

// SNP-09
#[cfg(kani)]
#[kani::proof]
#[kani::unwind(4)]
pub fn check_three_positions_independent() {
    let base_height: u32 = 840_000;
    let mut status = NodeProgressStatus::from_bootstrap(base_height);

    assert_eq!(status.active_chain_height(), base_height);
    assert_eq!(status.historical_validation_height(), 0);
    assert_eq!(status.projection_coverage_height(), base_height);

    status.connect_block_above_tip();
    assert_eq!(status.active_chain_height(), base_height + 1);
    assert_eq!(status.historical_validation_height(), 0);
    assert_eq!(status.projection_coverage_height(), base_height);

    status.step_historical_validation(10);
    assert_eq!(status.active_chain_height(), base_height + 1);
    assert_eq!(status.historical_validation_height(), 10);
    assert_eq!(status.projection_coverage_height(), base_height);

    assert_ne!(
        status.active_chain_height(),
        status.historical_validation_height()
    );
}

// SNP-11
#[cfg(kani)]
#[kani::proof]
#[kani::unwind(4)]
pub fn check_raw_body_unavailable_when_bodies_not_retained() {
    let base_height: u32 = 840_000;
    let query_height: u32 = kani::any();
    kani::assume(query_height <= base_height);
    let retain_historical_bodies: bool = kani::any();
    let mode = if retain_historical_bodies {
        HistoricalBodiesMode::Retained
    } else {
        HistoricalBodiesMode::Pruned
    };

    let storage = MockStorage::new(base_height, mode);
    let body_result = storage.load_raw_block_body(query_height);

    if retain_historical_bodies {
        assert!(body_result.is_ok());
    } else {
        assert!(matches!(
            body_result,
            Err(StorageError::HistoricalBodyUnavailable)
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashSet, VecDeque};

    #[test]
    fn test_snapshot_bootstrap_bfs_exhaustive_safety() {
        let init_state = State::init();
        assert!(safety(&init_state, HistoricalBodiesMode::Pruned));

        let mut visited: HashSet<State> = HashSet::new();
        let mut queue: VecDeque<State> = VecDeque::new();

        visited.insert(init_state.clone());
        queue.push_back(init_state);

        let mut actions = vec![
            Action::StreamSnapshot,
            Action::PublishValidSnapshot,
            Action::RejectInvalidUtxo,
            Action::AdvanceActiveChain,
            Action::AdvanceHistoricalValidation,
            Action::AdvanceProjectionCoverage,
            Action::Stutter,
        ];
        let verification_pairs = [(false, false), (false, true), (true, false), (true, true)];
        for (utxo_ok, index_ok) in verification_pairs {
            actions.push(Action::VerifyCommitments { utxo_ok, index_ok });
        }
        for height in 0..=MAX_HEIGHT {
            actions.push(Action::QueryHistoricalBody { height });
        }

        while let Some(current) = queue.pop_front() {
            for action in &actions {
                let next = step(&current, action, HistoricalBodiesMode::Pruned);
                assert!(safety(&next, HistoricalBodiesMode::Pruned));
                if visited.insert(next.clone()) {
                    queue.push_back(next);
                }
            }
        }

        assert_eq!(visited.len(), 170);
    }

    #[test]
    fn test_snapshot_bootstrap_negative_control_removed_utxo_guard() {
        let mut state = State::init();
        state = step(
            &state,
            &Action::StreamSnapshot,
            HistoricalBodiesMode::Pruned,
        );
        state = step(
            &state,
            &Action::VerifyCommitments {
                utxo_ok: false,
                index_ok: true,
            },
            HistoricalBodiesMode::Pruned,
        );
        assert_eq!(state.bootstrap_phase, BootstrapPhase::Verifying);
        assert!(!state.utxo_verified);

        let safe_next = step(
            &state,
            &Action::PublishValidSnapshot,
            HistoricalBodiesMode::Pruned,
        );
        assert_eq!(safe_next.bootstrap_phase, BootstrapPhase::Verifying);
        assert!(!safe_next.coins_published);
        assert!(safety_publication_requires_utxo_verification(&safe_next));

        let mutant_next = step_mutant_removed_utxo_verification_guard(
            &state,
            &Action::PublishValidSnapshot,
            HistoricalBodiesMode::Pruned,
        );
        assert_eq!(mutant_next.bootstrap_phase, BootstrapPhase::Ready);
        assert!(mutant_next.coins_published);
        assert!(!safety_publication_requires_utxo_verification(&mutant_next));
        assert!(!safety(&mutant_next, HistoricalBodiesMode::Pruned));
    }

    #[test]
    fn test_streaming_coins_and_script_live_single_pass() {
        let mut coin_sink = MockUnpublishedCoinSink::new();
        let mut script_sink = MockUnpublishedScriptLiveSink::new();
        {
            let mut observer = PairObserver::new(&mut coin_sink, &mut script_sink);
            for _ in 0..3 {
                let coin = SnapshotCoin::arbitrary();
                observer.observe_coin(&coin);
            }
            assert_eq!(observer.stream_passes(), 1);
        }
        assert_eq!(coin_sink.count(), 3);
        assert_eq!(script_sink.count(), 3);
    }

    #[test]
    fn test_no_publish_before_utxo_verification() {
        let anchor = [1u8; 32];
        let mut state = SnapshotBootstrapState::new(anchor, anchor);
        state.stream_unpublished_data();
        assert!(!state.is_coin_store_published());
        assert!(!state.is_script_live_published());

        assert!(state.verify_and_activate().is_ok());
        assert!(state.is_coin_store_published());
        assert!(state.is_script_live_published());

        let mut bad_state = SnapshotBootstrapState::new([2u8; 32], anchor);
        bad_state.stream_unpublished_data();
        assert!(bad_state.verify_and_activate().is_err());
        assert!(!bad_state.is_coin_store_published());
        assert!(!bad_state.is_script_live_published());
        assert!(bad_state.unpublished_data_discarded());
    }

    #[test]
    fn test_index_generation_attach_requires_verified_commitment() {
        let anchor = [5u8; 32];
        let mut bootstrap = IndexArtifactBootstrap::new(anchor);
        let res = bootstrap.verify_and_attach(anchor);
        assert!(res.is_ok());
        let Ok(attached) = res else {
            panic!("valid attachment");
        };
        assert!(attached.is_attached());
        assert_eq!(attached.restore_row_count(), 0);

        let mut bad_bootstrap = IndexArtifactBootstrap::new([6u8; 32]);
        assert!(bad_bootstrap.verify_and_attach(anchor).is_err());
    }

    #[test]
    fn test_index_failure_isolated_from_chainstate() {
        let controller = NodeBootstrapController::new(true, false);
        let outcome = controller.execute();
        assert!(!outcome.chainstate_closed);
        assert!(outcome.chainstate_active);
        assert!(outcome.index_invalidated);
        assert!(!outcome.index_attached);

        let bad_utxo = NodeBootstrapController::new(false, true);
        let bad_outcome = bad_utxo.execute();
        assert!(bad_outcome.chainstate_closed);
        assert!(!bad_outcome.chainstate_active);
    }

    #[test]
    fn test_three_positions_independent() {
        let mut status = NodeProgressStatus::from_bootstrap(100);
        assert_eq!(status.active_chain_height(), 100);
        assert_eq!(status.historical_validation_height(), 0);
        assert_eq!(status.projection_coverage_height(), 100);

        status.connect_block_above_tip();
        status.step_historical_validation(5);
        status.advance_projection_coverage(1);

        assert_eq!(status.active_chain_height(), 101);
        assert_eq!(status.historical_validation_height(), 5);
        assert_eq!(status.projection_coverage_height(), 101);
    }

    #[test]
    fn test_raw_body_unavailable_when_not_retained() {
        let storage = MockStorage::new(100, HistoricalBodiesMode::Pruned);
        assert!(matches!(
            storage.load_raw_block_body(50),
            Err(StorageError::HistoricalBodyUnavailable)
        ));
        assert!(storage.load_raw_block_body(150).is_ok());

        let retained_storage = MockStorage::new(100, HistoricalBodiesMode::Retained);
        assert!(retained_storage.load_raw_block_body(50).is_ok());
    }
}
