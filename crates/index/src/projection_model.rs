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
    use proptest::prelude::*;
    use proptest_state_machine::{ReferenceStateMachine, StateMachineTest, prop_state_machine};

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
        #![proptest_config(ProptestConfig { cases: 32, ..ProptestConfig::default() })]
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
}
