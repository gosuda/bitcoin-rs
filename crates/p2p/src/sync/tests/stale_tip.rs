//! Stale-tip policy: the one extra full-relay dial a stalled tip buys, and
//! the conditions that refuse it.

use super::super::{StaleTipState, tip_may_be_stale};
use super::*;

/// The network's target spacing: ten minutes, as every production chain
/// configures it.
const SPACING: Duration = Duration::from_secs(600);

/// A tip that stands still for three target spacings buys one extra dial, and
/// the next advance takes the allowance back at once.
#[test]
fn still_tip_buys_one_extra_dial_and_an_advance_withdraws_it() {
    let t0 = Instant::now();
    let mut state = StaleTipState::default();

    state.follow(100, 0, SPACING, t0);
    assert!(
        !state.extra_dial_allowed,
        "the first sight of a tip is progress, not staleness"
    );

    state.follow(100, 0, SPACING, t0 + Duration::from_mins(29));
    assert!(
        !state.extra_dial_allowed,
        "twenty-nine minutes of standing still is inside the bound"
    );

    state.follow(100, 0, SPACING, t0 + Duration::from_mins(40));
    assert!(
        state.extra_dial_allowed,
        "three intervals without a tip move is a stale tip"
    );

    state.follow(101, 0, SPACING, t0 + Duration::from_mins(41));
    assert!(
        !state.extra_dial_allowed,
        "an advancing tip withdraws the allowance without waiting for the next check"
    );
}

/// The staleness question is asked once per `STALE_CHECK_INTERVAL`, so a tip
/// crossing the three-interval bound between two checks is not judged until the
/// next one is due.
#[test]
fn the_staleness_question_is_paced() {
    let t0 = Instant::now();
    let mut state = StaleTipState::default();
    state.follow(100, 0, SPACING, t0);

    // Twenty-five minutes: the question is asked and answered "not yet", and
    // the next answer is not due until ten minutes later.
    state.follow(100, 0, SPACING, t0 + Duration::from_mins(25));
    assert!(!state.extra_dial_allowed, "inside the bound");
    state.follow(100, 0, SPACING, t0 + Duration::from_mins(31));
    assert!(
        !state.extra_dial_allowed,
        "past the bound but not yet due for a check"
    );
    state.follow(100, 0, SPACING, t0 + Duration::from_mins(35));
    assert!(
        state.extra_dial_allowed,
        "the check that is due finds the tip stale"
    );
}

/// Three target spacings of silence is the bound, and nothing in flight is the
/// other half of it.
#[test]
fn in_flight_bodies_hold_staleness_off() {
    let t0 = Instant::now();
    let mut state = StaleTipState {
        last_update: Some(t0),
        ..StaleTipState::default()
    };

    assert!(
        !tip_may_be_stale(&mut state, 0, SPACING, t0 + Duration::from_mins(30)),
        "exactly three intervals is not past the bound"
    );
    assert!(
        tip_may_be_stale(&mut state, 0, SPACING, t0 + Duration::from_mins(31)),
        "past three intervals with nothing in flight the tip is stale"
    );
    assert!(
        !tip_may_be_stale(&mut state, 4, SPACING, t0 + Duration::from_mins(31)),
        "bodies still arriving is progress, not a stalled tip"
    );
}
