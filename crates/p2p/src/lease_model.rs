//! Executable reference model for peer session and lease-ticket ownership.
//!
//! `Action` names come from the `PeerLeases` TLA sub-machines:
//! `Session.tla` owns `Start`, `HandshakeDone`, `BeginClose`, `FinishClose`,
//! `Seal`, `Done` and `Stutter`; `Lease.tla` owns `Env`, `Reserve`, `Issue`,
//! `Terminalize` and `Settle`. [`step`] is the same machine as
//! `docs/lean/PeerLeases/Safety.lean`, where `safety` is proved inductive.

pub(crate) const MAX_SESSIONS: u32 = 2;
pub(crate) const PHASE_ABSENT: u32 = 0;
pub(crate) const PHASE_HANDSHAKING: u32 = 1;
pub(crate) const PHASE_ESTABLISHED: u32 = 2;
pub(crate) const PHASE_CLOSING: u32 = 3;
pub(crate) const PHASE_CLOSED: u32 = 4;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct State {
    pub next_session: u32,
    pub phase: [u32; 2],
    pub current: u32,
    pub alloc: [u32; 2],
    pub ever: [u32; 2],
    pub rel: [u32; 2],
    pub freed: [u32; 2],
    pub ticket_phase: [u32; 2],
    pub closing: bool,
    pub custody: [u32; 2],
    pub input_open: bool,
    pub done: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Action {
    Start(usize),
    HandshakeDone(usize),
    BeginClose(usize),
    FinishClose(usize),
    Seal,
    Done,
    Env,
    Reserve(usize),
    Issue(usize),
    Terminalize(usize),
    Settle(usize),
    Stutter,
}

impl State {
    #[must_use]
    pub(crate) const fn init() -> Self {
        Self {
            next_session: 0,
            phase: [PHASE_ABSENT; 2],
            current: 0,
            alloc: [0; 2],
            ever: [0; 2],
            rel: [0; 2],
            freed: [0; 2],
            ticket_phase: [0; 2],
            closing: false,
            custody: [0; 2],
            input_open: true,
            done: false,
        }
    }
}

#[must_use]
pub(crate) fn step(state: &State, action: Action) -> Option<State> {
    if state.done && !matches!(action, Action::Stutter) {
        return None;
    }
    let mut next = *state;
    match action {
        Action::Start(session) => {
            let index = u32::try_from(session).ok()?;
            if index >= MAX_SESSIONS {
                return None;
            }
            let earlier_closed = session == 0 || state.phase[0] == PHASE_CLOSED;
            if !state.input_open
                || state.current != 0
                || state.next_session != index
                || state.phase[session] != PHASE_ABSENT
                || !earlier_closed
            {
                return None;
            }
            next.next_session = index + 1;
            next.phase[session] = PHASE_HANDSHAKING;
            next.current = index + 1;
        }
        Action::HandshakeDone(session)
        | Action::BeginClose(session)
        | Action::FinishClose(session) => {
            let (required, target) = match action {
                Action::HandshakeDone(_) => (PHASE_HANDSHAKING, PHASE_ESTABLISHED),
                Action::BeginClose(_) => (PHASE_ESTABLISHED, PHASE_CLOSING),
                _ => (PHASE_CLOSING, PHASE_CLOSED),
            };
            if session >= 2
                || state.phase[session] != required
                || state.current != u32::try_from(session).ok()? + 1
            {
                return None;
            }
            next.phase[session] = target;
            if target == PHASE_CLOSED {
                next.current = 0;
            }
        }
        Action::Seal => {
            if !state.input_open || state.done {
                return None;
            }
            next.input_open = false;
        }
        Action::Done => {
            if state.done || state.input_open || state.current != 0 {
                return None;
            }
            next.done = true;
        }
        Action::Env => {
            if state.done {
                return None;
            }
            next.closing = true;
        }
        Action::Stutter => {}
        Action::Reserve(ticket) => {
            if ticket >= 2 || state.alloc[ticket] != 0 || state.ticket_phase[ticket] != 0 {
                return None;
            }
            next.alloc[ticket] = 1;
            next.ticket_phase[ticket] = 1;
            next.custody[ticket] = 1;
        }
        Action::Issue(ticket) => {
            if ticket >= 2 || state.ticket_phase[ticket] != 1 {
                return None;
            }
            next.ticket_phase[ticket] = 2;
            next.ever[ticket] = 1;
        }
        Action::Terminalize(ticket) => {
            if ticket >= 2 || state.ticket_phase[ticket] != 2 {
                return None;
            }
            next.ticket_phase[ticket] = 3;
            next.rel[ticket] = 1;
            next.custody[ticket] = 2;
        }
        Action::Settle(ticket) => {
            if ticket >= 2
                || state.ticket_phase[ticket] != 3
                || !state.closing
                || state.custody[ticket] != 2
            {
                return None;
            }
            next.custody[ticket] = 3;
            next.freed[ticket] = 1;
        }
    }
    Some(next)
}

const fn ticket_safety(
    phase: u32,
    alloc: u32,
    ever: u32,
    rel: u32,
    custody: u32,
    freed: u32,
) -> bool {
    let phase_ok = match phase {
        0 => alloc == 0 && ever == 0 && rel == 0 && custody == 0 && freed == 0,
        1 | 2 => alloc == 1 && rel == 0 && custody == 1,
        _ => alloc == 1 && rel == 1 && custody >= 2,
    };
    phase_ok && ever <= alloc && rel <= alloc && freed <= rel && custody <= 3
}

// P2P-02
#[must_use]
pub(crate) const fn safety(state: &State) -> bool {
    state.next_session <= MAX_SESSIONS
        && state.phase[0] <= PHASE_CLOSED
        && state.phase[1] <= PHASE_CLOSED
        && state.current <= MAX_SESSIONS
        && (state.phase[0] == PHASE_CLOSED || state.next_session <= 1)
        && (state.phase[1] == PHASE_ABSENT || state.next_session == 2)
        && state.ticket_phase[0] <= 3
        && state.ticket_phase[1] <= 3
        && ticket_safety(
            state.ticket_phase[0],
            state.alloc[0],
            state.ever[0],
            state.rel[0],
            state.custody[0],
            state.freed[0],
        )
        && ticket_safety(
            state.ticket_phase[1],
            state.alloc[1],
            state.ever[1],
            state.rel[1],
            state.custody[1],
            state.freed[1],
        )
        && (!state.done || (!state.input_open && state.current == 0))
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use proptest_state_machine::{ReferenceStateMachine, StateMachineTest, prop_state_machine};

    use super::{Action, PHASE_ABSENT, PHASE_CLOSED, PHASE_CLOSING, State, safety, step};
    use crate::connection::{
        BlockForwardCredit, MAX_UNSOLICITED_BLOCK_FORWARDS, PeerLease, QueuedFrame,
    };

    fn admitted() -> PeerLease {
        let (outbound, inbound) = crossbeam_channel::bounded(4);
        drop(inbound);
        PeerLease::new(outbound)
    }

    struct Sessions {
        leases: [Option<PeerLease>; 2],
        credits: [Option<BlockForwardCredit>; 2],
        cancelled: [bool; 2],
        inbound: crossbeam_channel::Receiver<QueuedFrame>,
        created: u32,
    }

    impl Sessions {
        fn new() -> Self {
            let (outbound, inbound) = crossbeam_channel::bounded(4);
            drop(outbound);
            Self {
                leases: [None, None],
                credits: [None, None],
                cancelled: [false, false],
                inbound,
                created: 0,
            }
        }

        fn live(&self, session: usize) -> bool {
            self.leases[session].is_some()
        }
    }

    struct LeaseReference;

    const ACTIONS: u8 = 20;

    fn action(index: u8) -> Action {
        match index {
            0 => Action::Start(0),
            1 => Action::Start(1),
            2 => Action::HandshakeDone(0),
            3 => Action::HandshakeDone(1),
            4 => Action::BeginClose(0),
            5 => Action::BeginClose(1),
            6 => Action::FinishClose(0),
            7 => Action::FinishClose(1),
            8 => Action::Reserve(0),
            9 => Action::Reserve(1),
            10 => Action::Issue(0),
            11 => Action::Issue(1),
            12 => Action::Terminalize(0),
            13 => Action::Terminalize(1),
            14 => Action::Settle(0),
            15 => Action::Settle(1),
            16 => Action::Env,
            17 => Action::Stutter,
            18 => Action::Seal,
            _ => Action::Done,
        }
    }

    impl ReferenceStateMachine for LeaseReference {
        type State = State;
        type Transition = Action;

        fn init_state() -> BoxedStrategy<State> {
            Just(State::init()).boxed()
        }

        fn transitions(_state: &State) -> BoxedStrategy<Action> {
            (0_u8..ACTIONS).prop_map(action).boxed()
        }

        fn preconditions(state: &State, transition: &Action) -> bool {
            let ticket_live = match transition {
                Action::Reserve(ticket)
                | Action::Issue(ticket)
                | Action::Terminalize(ticket)
                | Action::Settle(ticket) => {
                    !matches!(state.phase[*ticket], PHASE_ABSENT | PHASE_CLOSED)
                }
                _ => true,
            };
            ticket_live && step(state, *transition).is_some()
        }

        fn apply(mut state: State, transition: &Action) -> State {
            if let Some(next) = step(&state, *transition) {
                state = next;
            }
            state
        }
    }

    struct LeaseMachine;

    impl StateMachineTest for LeaseMachine {
        type SystemUnderTest = Sessions;
        type Reference = LeaseReference;

        fn init_test(_ref_state: &State) -> Self::SystemUnderTest {
            Sessions::new()
        }

        fn apply(
            mut sut: Self::SystemUnderTest,
            _ref_state: &State,
            transition: <Self::Reference as ReferenceStateMachine>::Transition,
        ) -> Self::SystemUnderTest {
            match transition {
                Action::Start(session) => {
                    let (outbound, inbound) = crossbeam_channel::bounded(4);
                    drop(inbound);
                    sut.leases[session] = Some(PeerLease::new(outbound));
                    sut.cancelled[session] = false;
                    sut.created += 1;
                }
                Action::HandshakeDone(_)
                | Action::Seal
                | Action::Done
                | Action::Issue(_)
                | Action::Env
                | Action::Settle(_)
                | Action::Stutter => {}
                Action::BeginClose(session) => {
                    if let Some(lease) = sut.leases[session].as_ref() {
                        lease.cancel();
                        sut.cancelled[session] = lease.is_cancelled();
                    }
                }
                Action::FinishClose(session) => {
                    sut.leases[session] = None;
                    sut.cancelled[session] = false;
                }
                Action::Reserve(ticket) => {
                    let Some(lease) = sut.leases[ticket].as_ref() else {
                        panic!("the model reserves a ticket on a live session");
                    };
                    let source = lease.source(None);
                    let Some(credit) = lease.admit_block_forward(
                        source,
                        bitcoin_rs_primitives::Hash256::default(),
                        false,
                    ) else {
                        panic!("a live session admits the first unsolicited body");
                    };
                    sut.credits[ticket] = Some(credit);
                }
                Action::Terminalize(ticket) => {
                    sut.credits[ticket] = None;
                }
            }
            sut
        }

        fn check_invariants(sut: &Self::SystemUnderTest, ref_state: &State) {
            assert!(
                safety(ref_state),
                "the peer-lease safety predicate must hold after every step: {ref_state:?}"
            );
            for session in 0..2 {
                let phase = ref_state.phase[session];
                if phase == PHASE_ABSENT || phase == PHASE_CLOSED {
                    assert!(
                        !sut.live(session),
                        "a closed or absent model session owns no real lease"
                    );
                } else {
                    assert!(
                        sut.live(session),
                        "a handshaking, established or closing model session owns a real lease"
                    );
                }
                assert_eq!(
                    sut.cancelled[session],
                    phase == PHASE_CLOSING,
                    "the closing phase is exactly the real lease that reported cancellation"
                );
                let held = sut.credits[session].is_some();
                let reserved_or_issued = matches!(ref_state.ticket_phase[session], 1 | 2);
                assert_eq!(
                    held, reserved_or_issued,
                    "a held block-forward credit is exactly a reserved or issued ticket"
                );
            }
            assert_eq!(
                sut.created, ref_state.next_session,
                "the real session count matches the model's session counter"
            );
            assert!(
                sut.inbound.is_empty(),
                "no frames were sent during the model run"
            );
        }
    }

    // P2P-02
    prop_state_machine! {
        #![proptest_config(ProptestConfig { cases: 48, ..ProptestConfig::default() })]
        #[test]
        fn peer_leases_match_the_reference_model(sequential 1..16 => LeaseMachine);
    }

    #[test]
    fn safety_holds_from_init() {
        assert!(safety(&State::init()), "the initial state satisfies safety");
    }

    #[test]
    fn the_ticket_allowance_refuses_one_more_credit_than_the_bound() {
        let lease = admitted();
        let source = lease.source(None);
        let mut held = Vec::new();
        for _ in 0..MAX_UNSOLICITED_BLOCK_FORWARDS {
            let Some(credit) =
                lease.admit_block_forward(source, bitcoin_rs_primitives::Hash256::default(), false)
            else {
                panic!("the per-connection forward bound admits every credit up to the limit");
            };
            held.push(credit);
        }
        assert!(
            lease
                .admit_block_forward(source, bitcoin_rs_primitives::Hash256::default(), false)
                .is_none(),
            "the real per-connection bound refuses the credit past MAX_UNSOLICITED_BLOCK_FORWARDS"
        );
        assert!(!held.is_empty(), "credits were collected");
        drop(held);
        assert!(
            lease
                .admit_block_forward(source, bitcoin_rs_primitives::Hash256::default(), false)
                .is_some(),
            "released credits return the allowance"
        );
    }

    #[test]
    fn a_cancelled_lease_reports_itself_closed() {
        let lease = admitted();
        assert!(!lease.is_cancelled(), "a fresh lease is live");
        lease.cancel();
        assert!(
            lease.is_cancelled(),
            "the real lease reports the model's closed phase"
        );
    }
}
