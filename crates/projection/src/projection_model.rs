//! Executable reference model for projection handoff and index generations.
//!
//! Rust counterpart of the verified design models
//! `docs/models/ProjectionIndex/CommittedFactsHandoff.tla` and
//! `docs/models/ProjectionIndex/IndexGenerations.tla`, and
//! `docs/lean/ProjectionIndex/*.lean`, with the types, bounds, and
//! harness obligations of `.outline/proofs/projection-index/kani-spec.md`.
//!
//! Design model only: specifies the state machines and invariant safety.
//! Not an implementation refinement proof or physical durability proof.

#![cfg_attr(kani, allow(dead_code))]

#[cfg(kani)]
mod proofs;

pub(crate) mod handoff {
    pub(crate) const MAX_HEIGHT: u32 = 3;
    pub(crate) const QUEUE_BUDGET: usize = 2;
    pub(crate) const MAX_VERIFIED: u32 = 2;

    #[cfg_attr(not(kani), allow(dead_code))]
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub(crate) enum WakeMessage {
        Signal,
        BlockPayload { height: u32, payload_bytes: usize },
    }

    #[cfg_attr(not(kani), allow(dead_code))]
    impl WakeMessage {
        #[must_use]
        pub(crate) const fn carries_payload(&self) -> bool {
            matches!(self, Self::BlockPayload { .. })
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub(crate) enum HandoffAction {
        CommitBlock,
        VerifyHistorical,
        WorkerLiveStep,
        WorkerRecoveryStep,
        Reorganize { fork: u32 },
        Stutter,
    }

    #[derive(Clone, Debug, PartialEq, Eq, Hash)]
    pub(crate) struct HandoffState {
        pub(crate) applied_height: u32,
        pub(crate) verified_height: u32,
        pub(crate) coverage_height: u32,
        pub(crate) queue_len: usize,
        pub(crate) queue_bytes: usize,
        pub(crate) gap: bool,
        pub(crate) wake_pending: bool,
        pub(crate) last_wake_message: Option<WakeMessage>,
        pub(crate) live_body_reads: u64,
        pub(crate) recovery_body_reads: u64,
        pub(crate) reorg_count: u32,
    }

    impl HandoffState {
        #[must_use]
        pub(crate) const fn init() -> Self {
            Self {
                applied_height: 0,
                verified_height: 0,
                coverage_height: 0,
                queue_len: 0,
                queue_bytes: 0,
                gap: false,
                wake_pending: false,
                last_wake_message: None,
                live_body_reads: 0,
                recovery_body_reads: 0,
                reorg_count: 0,
            }
        }
    }

    // PRJ-01, PRJ-02, PRJ-04, PRJ-13, IDX-08
    #[must_use]
    pub(crate) fn safety(s: &HandoffState) -> bool {
        s.live_body_reads == 0
            && s.queue_bytes <= QUEUE_BUDGET
            && s.queue_len <= s.queue_bytes
            && u32::try_from(s.queue_len)
                .is_ok_and(|len| s.coverage_height + len <= s.applied_height)
            && (!s.gap || s.queue_bytes == 0 || s.queue_bytes <= QUEUE_BUDGET)
            && (s.gap || s.queue_bytes == s.queue_len)
            && s.verified_height <= MAX_VERIFIED
    }

    #[must_use]
    pub(crate) fn type_ok(s: &HandoffState) -> bool {
        s.applied_height <= MAX_HEIGHT
            && s.verified_height <= MAX_VERIFIED
            && s.coverage_height <= MAX_HEIGHT
            && s.queue_bytes <= QUEUE_BUDGET
            && s.queue_len <= QUEUE_BUDGET
            && s.live_body_reads == 0
            && s.recovery_body_reads <= u64::from(2 * MAX_HEIGHT)
            && s.reorg_count <= 1
    }

    #[must_use]
    pub(crate) fn step(s: &HandoffState, action: HandoffAction) -> HandoffState {
        let mut next = s.clone();
        match action {
            HandoffAction::CommitBlock => {
                if s.applied_height < MAX_HEIGHT {
                    next.applied_height += 1;
                    if s.queue_bytes < QUEUE_BUDGET {
                        next.queue_len += 1;
                        next.queue_bytes += 1;
                    } else {
                        next.gap = true;
                    }
                    next.wake_pending = true;
                    next.last_wake_message = Some(WakeMessage::Signal);
                }
            }
            HandoffAction::VerifyHistorical => {
                if s.verified_height < MAX_VERIFIED {
                    next.verified_height += 1;
                }
            }
            HandoffAction::WorkerLiveStep => {
                if !s.gap && s.queue_len > 0 {
                    next.queue_len -= 1;
                    next.queue_bytes -= 1;
                    next.coverage_height += 1;
                    next.wake_pending = false;
                    next.last_wake_message = None;
                }
            }
            HandoffAction::WorkerRecoveryStep => {
                if s.gap && s.coverage_height < s.applied_height {
                    next.queue_len = 0;
                    next.queue_bytes = 0;
                    next.coverage_height = s.coverage_height.saturating_add(1);
                    next.recovery_body_reads = s.recovery_body_reads.saturating_add(1);
                    next.gap = next.coverage_height != s.applied_height;
                    next.wake_pending = false;
                    next.last_wake_message = None;
                }
            }
            HandoffAction::Reorganize { fork } => {
                if s.reorg_count < 1 && s.applied_height > 1 && fork >= 1 && fork < s.applied_height
                {
                    next.applied_height = fork;
                    next.coverage_height = s.coverage_height.min(fork);
                    next.queue_len = 0;
                    next.queue_bytes = 0;
                    next.gap = true;
                    next.wake_pending = true;
                    next.last_wake_message = Some(WakeMessage::Signal);
                    next.reorg_count += 1;
                }
            }
            HandoffAction::Stutter => {}
        }
        next
    }

    // PRJ-04
    #[must_use]
    pub(crate) fn step_unbounded_queue(s: &HandoffState, action: HandoffAction) -> HandoffState {
        let mut next = s.clone();
        match action {
            HandoffAction::CommitBlock => {
                if s.applied_height < MAX_HEIGHT {
                    next.applied_height += 1;
                    next.queue_len += 1;
                    next.queue_bytes += 1;
                    next.wake_pending = true;
                    next.last_wake_message = Some(WakeMessage::Signal);
                }
            }
            _ => return step(s, action),
        }
        next
    }

    // IDX-08
    #[cfg_attr(not(kani), allow(dead_code))]
    #[must_use]
    pub(crate) fn step_mutant_wake_with_payload(
        s: &HandoffState,
        action: HandoffAction,
    ) -> HandoffState {
        let mut next = step(s, action);
        if let HandoffAction::CommitBlock = action {
            if s.applied_height < MAX_HEIGHT {
                next.last_wake_message = Some(WakeMessage::BlockPayload {
                    height: next.applied_height,
                    payload_bytes: 1_000_000,
                });
            }
        }
        next
    }
}

pub(crate) mod generations {
    pub(crate) const MAX_TIP: u32 = 4;
    pub(crate) const TAIL_BOUND: u32 = 2;
    pub(crate) const MAX_REORGS: u32 = 1;

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub(crate) enum GenerationAction {
        AppendBlock,
        SealGeneration,
        Reorganize { fork: u32 },
        QueryAnswer,
        Stutter,
    }

    #[derive(Clone, Debug, PartialEq, Eq, Hash)]
    pub(crate) struct GenerationsState {
        pub(crate) applied_tip: u32,
        pub(crate) tail_lo: u32,
        pub(crate) tail_hi: u32,
        pub(crate) active_gens_cover: u32,
        pub(crate) has_invalid_coverage: bool,
        pub(crate) has_segment_offset: bool,
        pub(crate) reorg_count: u32,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub(crate) struct LogicalEntry {
        pub(crate) height: u32,
        pub(crate) tx_count: u32,
    }

    #[must_use]
    pub(crate) const fn logical_entry_live(height: u32) -> LogicalEntry {
        LogicalEntry {
            height,
            tx_count: height.wrapping_mul(7) + 1,
        }
    }

    #[must_use]
    pub(crate) const fn logical_entry_bulk(height: u32) -> LogicalEntry {
        LogicalEntry {
            height,
            tx_count: height.wrapping_mul(7) + 1,
        }
    }

    impl GenerationsState {
        #[must_use]
        pub(crate) const fn init() -> Self {
            Self {
                applied_tip: 0,
                tail_lo: 1,
                tail_hi: 0,
                active_gens_cover: 0,
                has_invalid_coverage: false,
                has_segment_offset: false,
                reorg_count: 0,
            }
        }
    }

    // PRJ-05, PRJ-07, PRJ-09, REO-04, REO-05
    #[must_use]
    pub(crate) fn safety(s: &GenerationsState) -> bool {
        !s.has_invalid_coverage
            && s.active_gens_cover <= s.applied_tip
            && s.active_gens_cover < s.tail_lo
            && s.tail_hi <= s.applied_tip
            && !s.has_segment_offset
    }

    #[must_use]
    pub(crate) fn type_ok(s: &GenerationsState) -> bool {
        s.applied_tip <= MAX_TIP
            && s.tail_lo >= 1
            && s.tail_lo <= MAX_TIP + 2
            && s.tail_hi <= MAX_TIP
            && s.reorg_count <= MAX_REORGS
    }

    #[must_use]
    pub(crate) fn step(s: &GenerationsState, action: GenerationAction) -> GenerationsState {
        let mut next = s.clone();
        match action {
            GenerationAction::AppendBlock => {
                if s.applied_tip < MAX_TIP {
                    let new_tip = s.applied_tip + 1;
                    let new_lo = if s.tail_hi < s.tail_lo {
                        new_tip
                    } else {
                        s.tail_lo
                    };
                    next.applied_tip = new_tip;
                    next.tail_hi = new_tip;
                    next.tail_lo = new_lo;
                }
            }
            GenerationAction::SealGeneration => {
                if s.tail_hi >= s.tail_lo && s.tail_hi - s.tail_lo + 1 >= TAIL_BOUND {
                    let seal_last = s.tail_lo + TAIL_BOUND - 1;
                    next.tail_lo = seal_last + 1;
                    next.active_gens_cover = seal_last;
                }
            }
            GenerationAction::Reorganize { fork } => {
                if s.reorg_count < MAX_REORGS && s.applied_tip > 0 && fork < s.applied_tip {
                    next.applied_tip = fork;
                    next.tail_hi = fork;
                    if fork >= s.tail_lo {
                    } else {
                        next.tail_lo = fork + 1;
                        next.active_gens_cover = if s.active_gens_cover > fork {
                            0
                        } else {
                            s.active_gens_cover
                        };
                    }
                    next.reorg_count += 1;
                }
            }
            GenerationAction::QueryAnswer => {
                if s.applied_tip > 0 {
                    next.has_segment_offset = false;
                }
            }
            GenerationAction::Stutter => {}
        }
        next
    }

    // REO-04
    #[must_use]
    pub(crate) fn step_missing_deep_reorg_guard(
        s: &GenerationsState,
        action: GenerationAction,
    ) -> GenerationsState {
        let mut next = s.clone();
        match action {
            GenerationAction::Reorganize { fork } => {
                if s.reorg_count < MAX_REORGS && s.applied_tip > 0 && fork < s.applied_tip {
                    next.applied_tip = fork;
                    next.tail_hi = fork;
                    if fork >= s.tail_lo {
                    } else {
                        next.tail_lo = fork + 1;
                    }
                    next.reorg_count += 1;
                }
            }
            _ => return step(s, action),
        }
        next
    }
}

pub(crate) const MAX_PHASE: u32 = 2;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct State {
    pub applied_height: u32,
    pub watermark: u32,
    pub rows_committed: u32,
    pub phase: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Action {
    Wake,
    Prepare,
    CommitBatch,
    CaughtUp,
    Stutter,
}

impl State {
    #[must_use]
    pub(crate) const fn init(applied_height: u32) -> Self {
        Self {
            applied_height,
            watermark: 0,
            rows_committed: 0,
            phase: 0,
        }
    }
}

#[must_use]
pub(crate) const fn step(state: &State, action: Action) -> Option<State> {
    match action {
        Action::Wake => {
            if state.phase != 0 || state.watermark >= state.applied_height {
                return None;
            }
            Some(State { phase: 1, ..*state })
        }
        Action::Prepare => {
            if state.phase != 1 {
                return None;
            }
            Some(State { phase: 2, ..*state })
        }
        Action::CommitBatch => {
            if state.phase != 2 || state.watermark >= state.applied_height {
                return None;
            }
            Some(State {
                watermark: state.watermark + 1,
                rows_committed: state.rows_committed + 1,
                phase: 0,
                ..*state
            })
        }
        Action::CaughtUp => {
            if state.watermark != state.applied_height {
                return None;
            }
            Some(State { phase: 0, ..*state })
        }
        Action::Stutter => Some(*state),
    }
}

// IDX-06
#[must_use]
pub(crate) const fn safety(state: &State) -> bool {
    state.watermark <= state.applied_height
        && state.rows_committed <= state.watermark
        && state.phase <= MAX_PHASE
}

#[cfg(test)]
mod tests {
    use std::collections::{HashSet, VecDeque};

    use proptest::prelude::*;
    use proptest_state_machine::{ReferenceStateMachine, StateMachineTest, prop_state_machine};

    use super::generations::{
        GenerationAction, GenerationsState, MAX_REORGS, MAX_TIP, TAIL_BOUND, logical_entry_bulk,
        logical_entry_live, safety as generations_safety, step as generations_step,
        step_missing_deep_reorg_guard, type_ok as generations_type_ok,
    };
    use super::handoff::{
        HandoffAction, HandoffState, QUEUE_BUDGET, safety as handoff_safety, step as handoff_step,
        step_unbounded_queue, type_ok as handoff_type_ok,
    };
    use super::{Action, State, safety, step};
    use crate::index::{IndexCapabilities, IndexCapability, IndexWatermark, IndexWatermarks};

    const CAPABILITIES: [IndexCapability; 2] =
        [IndexCapability::TxLookup, IndexCapability::ScriptHistory];

    struct Projection {
        watermarks: IndexWatermarks,
        applied_height: u32,
        tip_hash: [u8; 32],
        committed: u32,
    }

    impl Projection {
        fn new(applied_height: u32) -> Self {
            let mut watermarks = IndexWatermarks::default();
            let genesis = IndexWatermark {
                height: 0,
                hash: [7; 32],
            };
            for capability in CAPABILITIES {
                watermarks.set(capability, Some(genesis));
            }
            Self {
                watermarks,
                applied_height,
                tip_hash: [7; 32],
                committed: 0,
            }
        }

        fn selected(&self) -> Option<u32> {
            self.watermarks
                .selected(IndexCapabilities::from_iter(CAPABILITIES))
                .ok()
                .flatten()
                .map(|mark| mark.height)
        }
    }

    struct ProjectionReference;

    impl ReferenceStateMachine for ProjectionReference {
        type State = State;
        type Transition = Action;

        fn init_state() -> BoxedStrategy<State> {
            Just(State::init(4)).boxed()
        }

        fn transitions(_state: &State) -> BoxedStrategy<Action> {
            prop_oneof![
                Just(Action::Wake),
                Just(Action::Prepare),
                Just(Action::CommitBatch),
                Just(Action::CaughtUp),
                Just(Action::Stutter),
            ]
            .boxed()
        }

        fn preconditions(state: &State, transition: &Action) -> bool {
            step(state, *transition).is_some()
        }

        fn apply(mut state: State, transition: &Action) -> State {
            if let Some(next) = step(&state, *transition) {
                state = next;
            }
            state
        }
    }

    struct ProjectionMachine;

    impl StateMachineTest for ProjectionMachine {
        type SystemUnderTest = Projection;
        type Reference = ProjectionReference;

        fn init_test(ref_state: &State) -> Self::SystemUnderTest {
            Projection::new(ref_state.applied_height)
        }

        fn apply(
            mut sut: Self::SystemUnderTest,
            ref_state: &State,
            transition: <Self::Reference as ReferenceStateMachine>::Transition,
        ) -> Self::SystemUnderTest {
            match transition {
                Action::CommitBatch => {
                    let cursor = IndexWatermark {
                        height: ref_state.watermark,
                        hash: sut.tip_hash,
                    };
                    for capability in CAPABILITIES {
                        sut.watermarks.set(capability, Some(cursor));
                    }
                    sut.committed += 1;
                }
                Action::CaughtUp => {
                    sut.applied_height = ref_state.applied_height;
                }
                Action::Wake | Action::Prepare | Action::Stutter => {}
            }
            sut
        }

        fn check_invariants(sut: &Self::SystemUnderTest, ref_state: &State) {
            assert!(
                safety(ref_state),
                "the projection safety predicate must hold after every step: {ref_state:?}"
            );
            assert_eq!(
                sut.selected(),
                Some(ref_state.watermark),
                "the real aligned watermark equals the model watermark"
            );
            let aligned = sut
                .watermarks
                .get(IndexCapability::TxLookup)
                .zip(sut.watermarks.get(IndexCapability::ScriptHistory))
                .is_some_and(|(left, right)| left == right);
            assert!(
                aligned,
                "every selected capability carries the same real watermark"
            );
            assert_eq!(
                sut.committed, ref_state.rows_committed,
                "each committed batch is one real watermark advance"
            );
            assert!(
                sut.selected()
                    .is_some_and(|height| height <= sut.applied_height),
                "the index never projects past the applied height"
            );
        }
    }

    // IDX-06
    prop_state_machine! {
        #![proptest_config(ProptestConfig {
            cases: std::env::var("PROPTEST_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(256),
            ..ProptestConfig::default()
        })]
        #[test]
        fn index_projection_matches_the_reference_model(sequential 1..12 => ProjectionMachine);
    }

    #[test]
    fn safety_holds_from_init() {
        assert!(
            safety(&State::init(4)),
            "the initial state satisfies safety"
        );
    }

    #[test]
    fn commit_batch_refused_when_watermark_reaches_applied_height() {
        let state = State {
            applied_height: 4,
            watermark: 4,
            rows_committed: 4,
            phase: 2,
        };
        assert_eq!(step(&state, Action::CommitBatch), None);
    }

    #[test]
    fn a_mismatched_capability_watermark_is_not_selected() {
        let mut watermarks = IndexWatermarks::default();
        watermarks.set(
            IndexCapability::TxLookup,
            Some(IndexWatermark {
                height: 1,
                hash: [1; 32],
            }),
        );
        watermarks.set(
            IndexCapability::ScriptHistory,
            Some(IndexWatermark {
                height: 2,
                hash: [2; 32],
            }),
        );
        assert!(
            watermarks
                .selected(IndexCapabilities::from_iter(CAPABILITIES))
                .is_err(),
            "the real owner refuses to project mismatched capability watermarks"
        );
    }

    // PRJ-01, PRJ-02, PRJ-04, PRJ-13, IDX-08
    #[test]
    fn exhaustive_handoff_transition_exploration() {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();

        let init = HandoffState::init();
        assert!(handoff_safety(&init));
        assert!(handoff_type_ok(&init));
        visited.insert(init.clone());
        queue.push_back(init);

        while let Some(state) = queue.pop_front() {
            let mut actions = vec![
                HandoffAction::CommitBlock,
                HandoffAction::VerifyHistorical,
                HandoffAction::WorkerLiveStep,
                HandoffAction::WorkerRecoveryStep,
                HandoffAction::Stutter,
            ];
            if state.reorg_count < 1 && state.applied_height > 1 {
                for fork in 1..state.applied_height {
                    actions.push(HandoffAction::Reorganize { fork });
                }
            }

            for action in actions {
                let next = handoff_step(&state, action);
                assert!(
                    handoff_safety(&next),
                    "safety violated at state {next:?} via {action:?}"
                );
                assert!(
                    handoff_type_ok(&next),
                    "type_ok violated at state {next:?} via {action:?}"
                );
                if visited.insert(next.clone()) {
                    queue.push_back(next);
                }
            }
        }

        assert_eq!(
            visited.len(),
            195,
            "handoff model state count must match TLC (195 distinct states)"
        );
    }

    // PRJ-04
    #[test]
    fn negative_control_unbounded_queue_push_violates_prj_04() {
        let mut s = HandoffState::init();
        for _ in 0..QUEUE_BUDGET {
            s = handoff_step(&s, HandoffAction::CommitBlock);
        }
        assert_eq!(s.queue_bytes, QUEUE_BUDGET);
        assert!(!s.gap);
        assert!(handoff_safety(&s));

        let mutant = step_unbounded_queue(&s, HandoffAction::CommitBlock);
        assert!(mutant.queue_bytes > QUEUE_BUDGET);
        assert!(
            !handoff_safety(&mutant),
            "unbounded queue push must violate PRJ-04 safety"
        );
    }

    // PRJ-05, PRJ-07, PRJ-09, REO-04, REO-05
    #[test]
    fn exhaustive_generations_transition_exploration() {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();

        let init = GenerationsState::init();
        assert!(generations_safety(&init));
        assert!(generations_type_ok(&init));
        visited.insert(init.clone());
        queue.push_back(init);

        while let Some(state) = queue.pop_front() {
            let mut actions = vec![
                GenerationAction::AppendBlock,
                GenerationAction::SealGeneration,
                GenerationAction::QueryAnswer,
                GenerationAction::Stutter,
            ];
            if state.reorg_count < MAX_REORGS && state.applied_tip > 0 {
                for fork in 0..state.applied_tip {
                    actions.push(GenerationAction::Reorganize { fork });
                }
            }

            for action in actions {
                let next = generations_step(&state, action);
                assert!(
                    generations_safety(&next),
                    "safety violated at state {next:?} via {action:?}"
                );
                assert!(
                    generations_type_ok(&next),
                    "type_ok violated at state {next:?} via {action:?}"
                );
                if visited.insert(next.clone()) {
                    queue.push_back(next);
                }
            }
        }

        assert_eq!(
            visited.len(),
            29,
            "generations state projection must reach all 29 valid configurations"
        );
    }

    // REO-04
    #[test]
    fn negative_control_missing_deep_reorg_retirement_guard_violates_reo_04() {
        let mut s = GenerationsState::init();
        for _ in 0..TAIL_BOUND {
            s = generations_step(&s, GenerationAction::AppendBlock);
        }
        s = generations_step(&s, GenerationAction::SealGeneration);
        assert_eq!(s.active_gens_cover, TAIL_BOUND);
        assert_eq!(s.tail_lo, TAIL_BOUND + 1);

        s = generations_step(&s, GenerationAction::AppendBlock);
        assert_eq!(s.applied_tip, TAIL_BOUND + 1);
        assert!(generations_safety(&s));

        let fork = 1;
        assert!(fork < s.tail_lo);
        assert!(s.active_gens_cover > fork);

        let mutant = step_missing_deep_reorg_guard(&s, GenerationAction::Reorganize { fork });
        assert_eq!(mutant.applied_tip, fork);
        assert_eq!(mutant.active_gens_cover, TAIL_BOUND);
        assert!(mutant.active_gens_cover > mutant.applied_tip);
        assert!(
            !generations_safety(&mutant),
            "omission of deep reorg retirement guard must violate REO-04"
        );
    }

    // PRJ-01
    #[test]
    fn live_path_reads_zero_block_bodies_when_consuming_facts() {
        let mut s = HandoffState::init();
        s = handoff_step(&s, HandoffAction::CommitBlock);
        assert_eq!(s.queue_len, 1);
        assert!(!s.gap);

        let next = handoff_step(&s, HandoffAction::WorkerLiveStep);
        assert_eq!(next.live_body_reads, 0);
        assert_eq!(next.coverage_height, 1);
        assert_eq!(next.queue_len, 0);
    }

    // PRJ-02
    #[test]
    fn recovery_path_reads_bodies_until_caught_up() {
        let mut s = HandoffState::init();
        for _ in 0..=QUEUE_BUDGET {
            s = handoff_step(&s, HandoffAction::CommitBlock);
        }
        assert!(s.gap);
        assert_eq!(s.coverage_height, 0);
        assert_eq!(s.applied_height, 3);

        s = handoff_step(&s, HandoffAction::WorkerRecoveryStep);
        assert_eq!(s.recovery_body_reads, 1);
        assert_eq!(s.coverage_height, 1);
        assert!(s.gap);

        s = handoff_step(&s, HandoffAction::WorkerRecoveryStep);
        assert_eq!(s.recovery_body_reads, 2);
        assert_eq!(s.coverage_height, 2);
        assert!(s.gap);

        s = handoff_step(&s, HandoffAction::WorkerRecoveryStep);
        assert_eq!(s.recovery_body_reads, 3);
        assert_eq!(s.coverage_height, 3);
        assert!(!s.gap);
    }

    // PRJ-13
    #[test]
    fn three_positions_independent_and_monotonic_on_non_reorg() {
        let mut s = HandoffState::init();
        s = handoff_step(&s, HandoffAction::CommitBlock);
        s = handoff_step(&s, HandoffAction::VerifyHistorical);
        s = handoff_step(&s, HandoffAction::WorkerLiveStep);

        assert_eq!(s.applied_height, 1);
        assert_eq!(s.verified_height, 1);
        assert_eq!(s.coverage_height, 1);

        let next = handoff_step(&s, HandoffAction::VerifyHistorical);
        assert_eq!(next.applied_height, 1);
        assert_eq!(next.verified_height, 2);
        assert_eq!(next.coverage_height, 1);
        assert!(next.applied_height >= s.applied_height);
        assert!(next.verified_height >= s.verified_height);
        assert!(next.coverage_height >= s.coverage_height);
    }

    // PRJ-05, REO-05
    #[test]
    fn shallow_reorg_preserves_sealed_generations() {
        let mut s = GenerationsState::init();
        for _ in 0..TAIL_BOUND {
            s = generations_step(&s, GenerationAction::AppendBlock);
        }
        s = generations_step(&s, GenerationAction::SealGeneration);
        assert_eq!(s.active_gens_cover, TAIL_BOUND);
        assert_eq!(s.tail_lo, TAIL_BOUND + 1);

        for _ in 0..TAIL_BOUND {
            s = generations_step(&s, GenerationAction::AppendBlock);
        }
        assert_eq!(s.applied_tip, 2 * TAIL_BOUND);

        let fork = s.tail_lo;
        let next = generations_step(&s, GenerationAction::Reorganize { fork });
        assert_eq!(next.active_gens_cover, s.active_gens_cover);
        assert_eq!(next.tail_hi, fork);
        assert!(generations_safety(&next));
    }

    // PRJ-09
    #[test]
    fn bulk_and_live_entries_are_logically_identical() {
        for h in 0..=MAX_TIP {
            let live = logical_entry_live(h);
            let bulk = logical_entry_bulk(h);
            assert_eq!(live, bulk);
        }
    }

    // PRJ-07
    #[test]
    fn query_answers_contain_no_segment_offsets() {
        let mut s = GenerationsState::init();
        s = generations_step(&s, GenerationAction::AppendBlock);
        let next = generations_step(&s, GenerationAction::QueryAnswer);
        assert!(!next.has_segment_offset);
        assert!(generations_safety(&next));
    }
}
