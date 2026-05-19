//! Property tests for BIP158 GCS encoding.

use bitcoin_rs_filters::gcs;
use proptest::prelude::*;

const CASES: u32 = 1_000;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(CASES))]

    #[test]
    fn encode_decode_round_trips_u64_sets(mut values in proptest::collection::vec(0_u64..(1_u64 << 40), 0..256)) {
        values.sort_unstable();
        values.dedup();
        let encoded = gcs::encode(&values, [0x42; 16]);
        let decoded = gcs::decode(&encoded, [0x42; 16])?;
        prop_assert_eq!(decoded, values);
    }
}
