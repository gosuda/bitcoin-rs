use super::*;

/// Done-when #629 (retained memory while a slow early job parks the join):
/// later jobs finish first and their results queue behind block one, so the
/// retained set is exactly one window. With tip-sized bodies the byte budget
/// must be what ends that window — the count cap alone would retain
/// gigabytes. Expectations are derived from the constants at runtime; the
/// issue forbids freezing either queue size in a permanent test.
#[test]
fn a_slow_early_job_retains_at_most_the_byte_budget() {
    // A near-tip body is about 2 MB (the documented figure behind the byte
    // cap); offered far past the count cap, the byte budget must end the
    // window first.
    let tip_block = 2 << 20;
    let offered = SCRIPT_BATCH_WINDOW * 4;
    let retained = window_len(std::iter::repeat_n(tip_block, offered));

    assert!(
        retained < SCRIPT_BATCH_WINDOW,
        "with tip-sized bodies the byte budget must bind before the count cap"
    );
    assert!(
        retained.saturating_mul(tip_block) <= SCRIPT_BATCH_MAX_BYTES,
        "retained window bytes must stay within the byte budget"
    );
    assert!(
        SCRIPT_BATCH_MAX_BYTES < offered.saturating_mul(tip_block),
        "this assertion is vacuous unless the offered work exceeds the byte budget"
    );

    // The budget must be the *binding* bound, not just an upper one: admit
    // the window the same set would fill with small early-chain blocks, so
    // the count cap alone is demonstrably reachable and the cut above is
    // attributable to bytes.
    let small_block = 256_usize;
    let retained_small = window_len(std::iter::repeat_n(small_block, offered));
    assert_eq!(
        retained_small, SCRIPT_BATCH_WINDOW,
        "small bodies must fill the window to its count cap"
    );
    assert!(
        retained < retained_small,
        "the byte budget must cut the tip-sized window below what the count cap admits"
    );
}
