//! Property tests for primitive hash and compact-size codecs.
use bitcoin_rs_primitives::{Hash256, varint};
use proptest::prelude::{ProptestConfig, any, prop_assert_eq, proptest};
use proptest::strategy::Strategy;

proptest! {
    #![proptest_config(ProptestConfig { cases: 1000, ..ProptestConfig::default() })]

    #[test]
    fn hash256_big_endian_string_roundtrips(bytes in any::<[u8; 32]>()) {
        let hash = Hash256::from_le_bytes(&bytes);
        let rendered = hash.to_string_be();
        let parsed = Hash256::from_str_be(&rendered)?;
        prop_assert_eq!(parsed, hash);
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 1000, ..ProptestConfig::default() })]

    #[test]
    fn compact_size_varint_roundtrips(value in any::<u64>()) {
        let encoded = varint::encode(value);
        let (decoded, consumed) = varint::decode(encoded.as_slice())?;
        prop_assert_eq!(decoded, value);
        prop_assert_eq!(consumed, encoded.len());
    }
}

#[test]
fn compact_size_varint_boundaries_roundtrip() -> Result<(), varint::VarintError> {
    for value in [
        0,
        0xfc,
        0xfd,
        0xffff,
        0x1_0000,
        0xffff_ffff,
        0x1_0000_0000,
        u64::MAX,
    ] {
        let encoded = varint::encode(value);
        let (decoded, consumed) = varint::decode(encoded.as_slice())?;
        assert_eq!(decoded, value);
        assert_eq!(consumed, encoded.len());
    }
    Ok(())
}

#[test]
fn any_array_strategy_is_used_for_hash_inputs() {
    let _strategy = any::<[u8; 32]>().prop_map(|bytes| Hash256::from_le_bytes(&bytes));
}
