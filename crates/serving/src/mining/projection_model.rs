pub(crate) const SHARE_CAP: u32 = 2;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct State {
    pub tip_gen: u32,
    pub active_gen: u32,
    pub pending_shares: u32,
    pub done: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Action {
    Advance,
    Accept,
    Drain,
    Finish,
    Stutter,
}

impl State {
    #[must_use]
    pub(crate) const fn init(tip_gen: u32) -> Self {
        Self {
            tip_gen,
            active_gen: 0,
            pending_shares: 0,
            done: false,
        }
    }
}

#[must_use]
pub(crate) const fn step(state: &State, action: Action) -> Option<State> {
    match action {
        Action::Advance => {
            if state.active_gen >= state.tip_gen || state.done {
                return None;
            }
            Some(State {
                active_gen: state.active_gen + 1,
                pending_shares: 0,
                ..*state
            })
        }
        Action::Accept => {
            if state.done || state.active_gen != state.tip_gen || state.pending_shares >= SHARE_CAP
            {
                return None;
            }
            Some(State {
                pending_shares: state.pending_shares + 1,
                ..*state
            })
        }
        Action::Drain => {
            if state.pending_shares == 0 {
                return None;
            }
            Some(State {
                pending_shares: state.pending_shares - 1,
                ..*state
            })
        }
        Action::Finish => {
            if state.done || state.active_gen != state.tip_gen {
                return None;
            }
            Some(State {
                done: true,
                pending_shares: 0,
                ..*state
            })
        }
        Action::Stutter => Some(*state),
    }
}

#[must_use]
pub(crate) const fn safety(state: &State) -> bool {
    state.active_gen <= state.tip_gen
        && state.pending_shares <= SHARE_CAP
        && (!state.done || (state.pending_shares == 0 && state.active_gen == state.tip_gen))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    use crate::mining::control::{
        BlockTemplateRequest, BlockTemplateResult, GenerateRequest, GeneratedBlock, MiningControl,
        MiningControlError, MiningInfo,
    };
    use crate::mining::generation_signal::MiningGenerationSignal;
    use proptest::prelude::*;
    use proptest_state_machine::{ReferenceStateMachine, StateMachineTest, prop_state_machine};

    use super::{Action, SHARE_CAP, State, safety, step};

    struct CountingControl {
        published: AtomicU32,
        pending_shares: AtomicU32,
    }

    fn unavailable() -> MiningControlError {
        MiningControlError::Unavailable("the model harness holds no mining chain state".into())
    }

    impl MiningControl for CountingControl {
        fn get_block_template(
            &self,
            _request: BlockTemplateRequest,
        ) -> Result<BlockTemplateResult, MiningControlError> {
            Err(unavailable())
        }

        fn mining_info(&self) -> Result<MiningInfo, MiningControlError> {
            Err(unavailable())
        }

        fn network_hash_ps(&self, _lookup: i64, _height: i64) -> Result<f64, MiningControlError> {
            Err(unavailable())
        }

        fn submit_block(
            &self,
            _payload: bitcoin_rs_consensus::primitives::BlockImage,
        ) -> Result<crate::mining::control::BlockValidationResult, MiningControlError> {
            Err(unavailable())
        }

        fn submit_header(
            &self,
            _header: bitcoin_rs_consensus::primitives::Header,
        ) -> Result<(), MiningControlError> {
            Err(unavailable())
        }

        fn publish_generation(&self) {
            self.published.fetch_add(1, Ordering::AcqRel);
            self.pending_shares.store(0, Ordering::Release);
        }

        fn publish_fee_delta_generation(&self, _fee_delta_sequence: u64) {
            self.published.fetch_add(1, Ordering::AcqRel);
        }

        fn generate(
            &self,
            _request: GenerateRequest,
        ) -> Result<Vec<GeneratedBlock>, MiningControlError> {
            Err(unavailable())
        }
    }

    struct Mining {
        signal: MiningGenerationSignal,
        control: Arc<CountingControl>,
        tip_gen: u32,
    }

    impl Mining {
        fn new(tip_gen: u32) -> Self {
            let control = Arc::new(CountingControl {
                published: AtomicU32::new(0),
                pending_shares: AtomicU32::new(0),
            });
            let signal = MiningGenerationSignal::new();
            let shared: Arc<CountingControl> = Arc::clone(&control);
            let control_dyn: Arc<dyn MiningControl> = shared;
            signal.attach(&control_dyn);
            Self {
                signal,
                control,
                tip_gen,
            }
        }
    }

    struct MiningReference;

    impl ReferenceStateMachine for MiningReference {
        type State = State;
        type Transition = Action;

        fn init_state() -> BoxedStrategy<State> {
            Just(State::init(4)).boxed()
        }

        fn transitions(_state: &State) -> BoxedStrategy<Action> {
            prop_oneof![
                Just(Action::Advance),
                Just(Action::Accept),
                Just(Action::Drain),
                Just(Action::Finish),
                Just(Action::Stutter),
            ]
            .boxed()
        }

        fn preconditions(state: &State, transition: &Action) -> bool {
            match transition {
                Action::Advance => !state.done && state.active_gen < state.tip_gen,
                Action::Accept => {
                    !state.done
                        && state.active_gen == state.tip_gen
                        && state.pending_shares < SHARE_CAP
                }
                Action::Drain => state.pending_shares > 0,
                Action::Finish => !state.done && state.active_gen == state.tip_gen,
                Action::Stutter => true,
            }
        }

        #[expect(
            clippy::expect_used,
            reason = "preconditions admit every applied transition"
        )]
        fn apply(state: State, transition: &Action) -> State {
            step(&state, *transition).expect("preconditions admit every applied transition")
        }
    }

    struct MiningMachine;

    impl StateMachineTest for MiningMachine {
        type SystemUnderTest = Mining;
        type Reference = MiningReference;

        fn init_test(ref_state: &State) -> Self::SystemUnderTest {
            Mining::new(ref_state.tip_gen)
        }

        #[expect(
            clippy::expect_used,
            reason = "the reference model asserts its own drain precondition"
        )]
        fn apply(
            mut sut: Self::SystemUnderTest,
            ref_state: &State,
            transition: <Self::Reference as ReferenceStateMachine>::Transition,
        ) -> Self::SystemUnderTest {
            match transition {
                Action::Advance => sut.signal.publish_generation(),
                Action::Accept => {
                    sut.control.pending_shares.fetch_add(1, Ordering::AcqRel);
                }
                Action::Drain => {
                    sut.control
                        .pending_shares
                        .try_update(Ordering::AcqRel, Ordering::Acquire, |held| {
                            held.checked_sub(1)
                        })
                        .expect("the model drains only a pending share");
                }
                Action::Finish => {
                    sut.tip_gen = ref_state.tip_gen;
                    sut.control.pending_shares.store(0, Ordering::Release);
                }
                Action::Stutter => {}
            }
            sut
        }

        fn check_invariants(sut: &Self::SystemUnderTest, ref_state: &State) {
            assert!(
                safety(ref_state),
                "the mining safety predicate must hold after every step: {ref_state:?}"
            );
            assert!(
                sut.control.published.load(Ordering::Acquire) <= sut.tip_gen,
                "the real generation wake never leads the tip generation"
            );
            assert!(
                sut.control.pending_shares.load(Ordering::Acquire) <= SHARE_CAP,
                "the real pending-share set stays inside the per-template cap"
            );
            assert_eq!(
                sut.control.pending_shares.load(Ordering::Acquire),
                ref_state.pending_shares,
                "the real pending-share count is the model's share count"
            );
        }
    }

    fn projection_model_cases() -> u32 {
        std::env::var("PROPTEST_CASES")
            .ok()
            .and_then(|c| c.parse().ok())
            .unwrap_or(256)
    }

    // POOL-05
    prop_state_machine! {
        #![proptest_config(ProptestConfig { cases: projection_model_cases(), ..ProptestConfig::default() })]
        #[test]
        fn mining_projection_matches_the_reference_model(sequential 1..24 => MiningMachine);
    }

    fn projection_action(index: u8) -> Action {
        match index {
            0 => Action::Advance,
            1 => Action::Accept,
            2 => Action::Drain,
            3 => Action::Finish,
            _ => Action::Stutter,
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: projection_model_cases(), ..ProptestConfig::default() })]

        // POOL-05
        #[test]
        fn projection_model_safety_holds_for_arbitrary_command_sequences(
            commands in prop::collection::vec(any::<u8>(), 0..48)
        ) {
            let mut state = State::init(4);
            prop_assert!(safety(&state), "initial state satisfies safety: {state:?}");
            for raw in commands {
                let action = projection_action(raw % 5);
                if let Some(next) = step(&state, action) {
                    state = next;
                }
                prop_assert!(
                    safety(&state),
                    "inductive safety holds after action {action:?}: {state:?}"
                );
            }
        }
    }

    #[test]
    fn safety_holds_from_init() {
        assert!(
            safety(&State::init(4)),
            "the initial state satisfies safety"
        );
    }

    #[expect(
        clippy::expect_used,
        reason = "the test asserts each modelled step is admissible"
    )]
    #[test]
    fn a_share_past_the_cap_is_blocked() {
        let mut state = State::init(1);
        state = step(&state, Action::Advance).expect("the tip admits an advance");
        state = step(&state, Action::Accept).expect("a caught-up template accepts a share");
        state = step(&state, Action::Accept).expect("the second share fits the cap");
        assert_eq!(step(&state, Action::Accept), None);
    }

    // POOL-05
    #[expect(
        clippy::expect_used,
        reason = "the test asserts the retirement step is admissible"
    )]
    #[test]
    fn finish_retires_the_active_job_with_pending_shares() {
        let mut state = State::init(1);
        state = step(&state, Action::Advance).expect("the tip admits an advance");
        state = step(&state, Action::Accept).expect("a caught-up template accepts a share");
        state = step(&state, Action::Accept).expect("the second share fits the cap");
        let retired = step(&state, Action::Finish).expect("Applied retires with pending shares");
        assert!(retired.done, "the terminal step marks the machine done");
        assert_eq!(
            retired.pending_shares, 0,
            "retirement zeroes pending shares"
        );
        assert_eq!(
            retired.active_gen, retired.tip_gen,
            "retirement leaves the tip active"
        );
        assert!(safety(&retired), "the retired state satisfies safety");
    }
}
