//! Executable reference model for the ordered chain-admission pipeline.
//!
//! [`step`] is the same machine as `docs/lean/ChainAdmission/Safety.lean`,
//! where `safety` is proved inductive. `Action` names come from the
//! `ChainAdmission` TLA actions; `ReleaseWriter`, `AcquireReader` and
//! `ReleaseReader` name reader-gate control the TLA sub-machines do not carry.
//! The model folds `Commit.tla` `MarkBody`, `MarkUndo`, `SyncFile` and
//! `SyncDirectory` into [`Action::Prove`] and [`Action::Commit`], and
//! `Frontier.tla` Complete into [`Action::Finish`]; `CloseInput` is absent
//! because the driven owner never closes admission. One
//! `Chainstate::apply_block` call performs [`Action::Commit`] and
//! [`Action::Publish`] inside one transition, so those two model steps are
//! observable only at the call boundary.

pub(crate) const MAX_ATTEMPTS: u32 = 4;
pub(crate) const JOB_SLOTS: u32 = 12;
pub(crate) const COUNTER_BOUND: u32 = 1_024;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct State {
    pub attempts: u32,
    pub jobs: u32,
    pub proposed: u32,
    pub committed: u32,
    pub published: u32,
    pub writer: u32,
    pub reader: u32,
    pub subscribed: u32,
    pub cursor: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Action {
    /// TLA `StartJob`: allocate one job slot for a transition from the live tip.
    StartJob,
    /// TLA `Prove`: stage the candidate block for the next height.
    Prove,
    /// TLA `Commit`: commit the staged batch to the durable head.
    Commit,
    /// TLA `Publish`: publish the committed tip to readers and observers.
    Publish,
    /// TLA `Fail`: a staging or validation refusal commits nothing.
    Fail,
    /// TLA `Retry`: retry the same candidate under a fresh stamp.
    Retry,
    /// TLA `Finish`: release the job slot.
    Finish,
    /// TLA `Admit`: install the staged-tip observer.
    Admit,
    /// TLA `Serve`: consume one published tip at the observer cursor.
    Serve,
    /// No TLA action: take the chain-transition reservation (the TLA writer flag).
    AcquireWriter,
    /// No TLA action: release the chain-transition reservation.
    ReleaseWriter,
    /// No TLA action: take a stable-view read of the applied tip.
    AcquireReader,
    /// No TLA action: release the applied-tip read.
    ReleaseReader,
    Stutter,
}

impl Action {
    pub(crate) const ALL: [Self; 14] = [
        Self::StartJob,
        Self::Prove,
        Self::Commit,
        Self::Publish,
        Self::Fail,
        Self::Retry,
        Self::Finish,
        Self::Admit,
        Self::Serve,
        Self::AcquireWriter,
        Self::ReleaseWriter,
        Self::AcquireReader,
        Self::ReleaseReader,
        Self::Stutter,
    ];

    #[must_use]
    pub(crate) fn from_index(index: u8) -> Option<Self> {
        Self::ALL.get(usize::from(index)).copied()
    }
}

impl State {
    #[must_use]
    pub(crate) const fn init() -> Self {
        Self {
            attempts: 0,
            jobs: 0,
            proposed: 0,
            committed: 0,
            published: 0,
            writer: 0,
            reader: 0,
            subscribed: 0,
            cursor: 0,
        }
    }
}

/// Returns the successor state, or `None` when the action is blocked.
///
/// `None` is the Lean model's blocked action, which leaves the state unchanged.
#[must_use]
pub(crate) const fn step(state: &State, action: Action) -> Option<State> {
    let next = match action {
        Action::StartJob => {
            if state.jobs >= JOB_SLOTS {
                return None;
            }
            State {
                jobs: state.jobs + 1,
                ..*state
            }
        }
        Action::Finish => {
            if state.jobs == 0 {
                return None;
            }
            State {
                jobs: state.jobs - 1,
                ..*state
            }
        }
        Action::Prove => {
            if state.proposed >= COUNTER_BOUND {
                return None;
            }
            State {
                proposed: state.proposed + 1,
                ..*state
            }
        }
        Action::Commit => {
            if state.committed >= state.proposed {
                return None;
            }
            State {
                committed: state.committed + 1,
                ..*state
            }
        }
        Action::Publish => {
            if state.published >= state.committed {
                return None;
            }
            State {
                published: state.published + 1,
                ..*state
            }
        }
        Action::Fail => {
            if state.attempts >= MAX_ATTEMPTS {
                return None;
            }
            State {
                attempts: state.attempts + 1,
                ..*state
            }
        }
        Action::Retry | Action::Stutter => *state,
        Action::Admit => State {
            subscribed: 1,
            cursor: 0,
            ..*state
        },
        Action::Serve => {
            if state.subscribed != 1 || state.cursor >= state.published {
                return None;
            }
            State {
                cursor: state.cursor + 1,
                ..*state
            }
        }
        Action::AcquireWriter => {
            if state.reader != 0 {
                return None;
            }
            State {
                writer: 1,
                ..*state
            }
        }
        Action::ReleaseWriter => State {
            writer: 0,
            ..*state
        },
        Action::AcquireReader => {
            if state.writer != 0 {
                return None;
            }
            State {
                reader: 1,
                ..*state
            }
        }
        Action::ReleaseReader => State {
            reader: 0,
            ..*state
        },
    };
    Some(next)
}

// RCV-02, SYNC-05
#[must_use]
pub(crate) const fn safety(state: &State) -> bool {
    state.attempts <= MAX_ATTEMPTS
        && state.jobs <= JOB_SLOTS
        && state.published <= state.committed
        && state.committed <= state.proposed
        && state.proposed <= COUNTER_BOUND
        && state.writer + state.reader <= 1
        && state.cursor <= state.published
        && (state.subscribed == 1 || state.cursor == 0)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use parking_lot::Mutex;

    use bitcoin_rs_primitives::{Block, BlockHash, BlockPayload, Network};
    use bitcoin_rs_utxo::UtxoSet;
    use proptest::prelude::*;
    use proptest_state_machine::{ReferenceStateMachine, StateMachineTest, prop_state_machine};

    use super::{Action, State, safety, step};
    use crate::test_fixtures::{StagedFire, handles, seed_genesis, staging_recorder};

    struct Admissions {
        chainstate: crate::Chainstate,
        parent: BlockHash,
        next_height: u32,
        prepared: Option<Block>,
        proposals: u32,
        attempts: u32,
        delivered: u32,
        fires: Arc<Mutex<Vec<StagedFire>>>,
    }

    fn next_block(parent: BlockHash, height: u32) -> Block {
        match bitcoin_rs_chain::regtest_fixture::mined_regtest_child_at(parent, height) {
            Ok(block) => block,
            Err(e) => panic!("a regtest child mines at every height: {e}"),
        }
    }

    fn false_coinbase(block: &Block) -> Block {
        let mut broken = block.clone();
        let Some(coinbase) = broken.txs.first_mut() else {
            return broken;
        };
        let Some(output) = coinbase.outputs.first_mut() else {
            return broken;
        };
        output.value = bitcoin_rs_primitives::Amount::from_sat(1);
        broken
    }

    impl Admissions {
        fn new() -> Self {
            let chainstate = handles(Network::Regtest, Arc::new(UtxoSet::new()));
            let tip = match seed_genesis(&chainstate) {
                Ok(tip) => tip,
                Err(e) => panic!("the genesis tip seeds: {e}"),
            };
            Self {
                chainstate,
                parent: BlockHash::from(tip.hash),
                next_height: 1,
                prepared: None,
                proposals: 0,
                attempts: 0,
                delivered: 0,
                fires: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn tip_height(&self) -> u32 {
            self.chainstate
                .applied_tip_snapshot()
                .map_or(0, |tip| tip.height)
        }

        fn take_prepared(&mut self) -> Block {
            let height = self.next_height;
            self.prepared
                .take()
                .unwrap_or_else(|| next_block(self.parent, height))
        }

        fn committed(&self) -> u32 {
            match self.chainstate.durable_head.load() {
                Ok(head) => head.map_or(0, |h| h.height),
                Err(e) => panic!("the in-memory durable head reads: {e}"),
            }
        }

        fn pending_fires(&self) -> usize {
            self.fires.lock().len()
        }
    }

    struct AdmissionReference;

    impl ReferenceStateMachine for AdmissionReference {
        type State = State;
        type Transition = Action;

        fn init_state() -> BoxedStrategy<State> {
            Just(State::init()).boxed()
        }

        fn transitions(_state: &State) -> BoxedStrategy<Action> {
            (0_u8..14)
                .prop_map(|index| match Action::from_index(index) {
                    Some(a) => a,
                    None => panic!("the index {index} names an action"),
                })
                .boxed()
        }

        fn preconditions(state: &State, transition: &Action) -> bool {
            let admitted = match transition {
                Action::Admit => state.subscribed == 0 && state.committed == 0,
                Action::Commit | Action::Fail => state.committed < state.proposed,
                _ => true,
            };
            admitted && step(state, *transition).is_some()
        }

        fn apply(mut state: State, transition: &Action) -> State {
            if let Some(next) = step(&state, *transition) {
                state = next;
            }
            state
        }
    }

    struct AdmissionMachine;

    impl StateMachineTest for AdmissionMachine {
        type SystemUnderTest = Admissions;
        type Reference = AdmissionReference;

        fn init_test(_ref_state: &State) -> Self::SystemUnderTest {
            Admissions::new()
        }

        fn apply(
            mut sut: Self::SystemUnderTest,
            ref_state: &State,
            transition: <Self::Reference as ReferenceStateMachine>::Transition,
        ) -> Self::SystemUnderTest {
            match transition {
                Action::StartJob | Action::AcquireWriter => {
                    let reservation = match sut.chainstate.lock_transition() {
                        Ok(r) => r,
                        Err(e) => panic!("admission is open for a transition: {e}"),
                    };
                    drop(reservation);
                }
                Action::AcquireReader => {
                    assert!(
                        sut.chainstate.applied_tip_snapshot().is_some(),
                        "the applied tip is readable whenever the model admits a reader"
                    );
                }
                Action::Prove => {
                    sut.prepared = Some(next_block(sut.parent, sut.next_height));
                    sut.proposals += 1;
                }
                Action::Commit => {
                    let block = sut.take_prepared();
                    let outcome = match sut
                        .chainstate
                        .apply_block(&BlockPayload::from_local(block.clone()))
                    {
                        Ok(o) => o,
                        Err(e) => panic!("a valid regtest block commits: {e}"),
                    };
                    assert_eq!(
                        outcome.tip.height, ref_state.committed,
                        "the real applied height must equal the model's committed counter"
                    );
                    sut.parent = block.block_hash();
                    sut.next_height += 1;
                }
                Action::Fail => {
                    let block = sut.take_prepared();
                    let error = match sut
                        .chainstate
                        .apply_block(&BlockPayload::from_local(false_coinbase(&block)))
                    {
                        Err(e) => e,
                        Ok(_) => panic!("a block with a broken proof of work is refused"),
                    };
                    assert!(
                        matches!(error, crate::ApplyError::Consensus(_)),
                        "the refusal must be the predicted consensus failure: {error:?}"
                    );
                    sut.attempts += 1;
                    sut.prepared = Some(next_block(sut.parent, sut.next_height));
                }
                Action::Publish => {
                    assert_eq!(
                        sut.tip_height(),
                        ref_state.committed,
                        "publication is atomic with the commit, so the applied tip is the committed height"
                    );
                }
                Action::Serve => {
                    let fire = sut.fires.lock().remove(0);
                    assert_eq!(
                        fire.staged_height, ref_state.cursor,
                        "each delivered fire is the next published height"
                    );
                    assert_eq!(
                        fire.published.map(|(_, height)| height),
                        fire.staged_height.checked_sub(1),
                        "the staging notification reports the parent tip, before publication"
                    );
                    sut.delivered += 1;
                }
                Action::Admit => {
                    let recorder = staging_recorder(&sut.chainstate, &sut.fires);
                    assert!(
                        sut.chainstate.set_tip_staged(recorder).is_ok(),
                        "the staged hook installs once"
                    );
                }
                Action::Retry
                | Action::Finish
                | Action::ReleaseWriter
                | Action::ReleaseReader
                | Action::Stutter => {}
            }
            sut
        }

        fn check_invariants(sut: &Self::SystemUnderTest, ref_state: &State) {
            assert!(
                safety(ref_state),
                "the ordered-commit safety predicate must hold after every step: {ref_state:?}"
            );
            assert_eq!(
                sut.committed(),
                ref_state.committed,
                "the durable head height is the model's committed counter"
            );
            assert_eq!(
                sut.tip_height(),
                ref_state.committed,
                "the applied tip is the durable head height: publication is atomic with the commit"
            );
            assert_eq!(
                sut.proposals, ref_state.proposed,
                "every Prove action proposes exactly one block"
            );
            assert_eq!(
                sut.attempts, ref_state.attempts,
                "every Fail action is one refused attempt"
            );
            assert_eq!(
                sut.delivered, ref_state.cursor,
                "every Serve action consumes exactly one published tip"
            );
            if ref_state.subscribed == 1 {
                assert_eq!(
                    sut.pending_fires(),
                    match usize::try_from(ref_state.committed - ref_state.cursor) {
                        Ok(expected) => expected,
                        Err(e) => panic!("the undelivered count fits usize: {e}"),
                    },
                    "the observer queue holds exactly the committed tips not yet served"
                );
            }
        }
    }

    // RCV-02, SYNC-05
    prop_state_machine! {
        #![proptest_config(ProptestConfig { cases: 48, ..ProptestConfig::default() })]
        #[test]
        fn chain_admission_matches_the_reference_model(sequential 1..20 => AdmissionMachine);
    }

    #[test]
    fn safety_holds_from_init() {
        assert!(safety(&State::init()), "the initial state satisfies safety");
    }

    #[test]
    fn blocked_actions_return_no_successor() {
        let state = State::init();
        assert_eq!(step(&state, Action::Finish), None);
        assert_eq!(step(&state, Action::Publish), None);
        assert_eq!(step(&state, Action::Serve), None);
        assert_eq!(
            step(&state, Action::AcquireWriter),
            Some(State { writer: 1, ..state })
        );
        let reserved = State { writer: 1, ..state };
        assert_eq!(step(&reserved, Action::AcquireReader), None);
    }
}
