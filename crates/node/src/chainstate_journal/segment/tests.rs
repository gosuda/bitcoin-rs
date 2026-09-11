//! CONTRACT v1: docs/contracts/recovery.md, JRN-SEGMENT-01.
use super::*;

#[test]
fn segment_names_round_trip_the_full_generation_range() {
    assert_eq!(segment_name(0), "segment-0000000000.log");
    assert_eq!(segment_name(u64::MAX), "segment-18446744073709551615.log");
    for generation in [0, 9, 10, 9_999_999_999, 10_000_000_000, u64::MAX] {
        assert_eq!(
            parse_segment_name(&segment_name(generation)),
            Some(generation)
        );
    }
}

#[test]
fn segment_parser_preserves_existing_decimal_acceptance() {
    // Padding is a writer convention, not an extra recovery rejection rule.
    assert_eq!(parse_segment_name("segment-7.log"), Some(7));
    assert_eq!(
        parse_segment_name("segment-00000000000000000000000000000000.log"),
        Some(0)
    );
    for name in [
        "segment-.log",
        "segment--1.log",
        "segment-+1.log",
        "segment-1a.log",
        "segment-18446744073709551616.log",
        "segment-000000000000000000000000000000000.log",
        "other-0000000001.log",
        "segment-0000000001.log.tmp",
    ] {
        assert_eq!(parse_segment_name(name), None, "accepted {name}");
    }
}
