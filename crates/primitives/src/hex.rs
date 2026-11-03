#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum HexError {
    #[error("hex string has an odd length")]
    OddLength,
    #[error("hex string has an invalid digit at offset {offset}")]
    InvalidDigit { offset: usize },
    #[error("hex string has {got} digits, expected {expected}")]
    WrongLength { expected: usize, got: usize },
}

#[must_use]
pub fn hex_encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[must_use]
pub const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[must_use]
pub fn is_lowercase_hex(text: &str) -> bool {
    text.bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub fn hex_decode(text: &str) -> Result<Vec<u8>, HexError> {
    let (pairs, odd_tail) = text.as_bytes().as_chunks::<2>();
    if !odd_tail.is_empty() {
        return Err(HexError::OddLength);
    }
    pairs
        .iter()
        .enumerate()
        .map(|(index, pair)| pair_value(*pair, index * 2))
        .collect()
}

pub fn hex_decode_array<const N: usize>(text: &str) -> Result<[u8; N], HexError> {
    let expected = N.saturating_mul(2);
    if text.len() != expected {
        return Err(HexError::WrongLength {
            expected,
            got: text.len(),
        });
    }
    let mut out = [0_u8; N];
    for (index, (slot, pair)) in out
        .iter_mut()
        .zip(text.as_bytes().as_chunks::<2>().0)
        .enumerate()
    {
        *slot = pair_value(*pair, index * 2)?;
    }
    Ok(out)
}

fn pair_value(pair: [u8; 2], offset: usize) -> Result<u8, HexError> {
    let high = hex_nibble(pair[0]).ok_or(HexError::InvalidDigit { offset })?;
    let low = hex_nibble(pair[1]).ok_or(HexError::InvalidDigit { offset: offset + 1 })?;
    Ok((high << 4) | low)
}

#[cfg(test)]
mod tests {
    use super::hex_encode;
    use super::{HexError, hex_decode, hex_decode_array, is_lowercase_hex};
    use proptest::prelude::*;

    fn proptest_config(default_cases: u32) -> ProptestConfig {
        let cases = std::env::var("PROPTEST_CASES")
            .ok()
            .and_then(|val| val.parse().ok())
            .unwrap_or(default_cases);
        ProptestConfig {
            cases,
            ..ProptestConfig::default()
        }
    }

    fn boundary_byte_strategy() -> impl Strategy<Value = u8> {
        prop_oneof![
            3 => any::<u8>(),
            1 => prop::sample::select(vec![0x00, 0x01, 0x0f, 0x10, 0x7f, 0x80, 0xfe, 0xff]),
        ]
    }

    fn boundary_bytes_strategy() -> impl Strategy<Value = Vec<u8>> {
        prop_oneof![
            1 => prop::sample::select(vec![
                vec![],
                vec![0x00],
                vec![0xff],
                vec![0x00; 32],
                vec![0xff; 32],
                (0..32u8).collect(),
            ]),
            3 => prop::collection::vec(boundary_byte_strategy(), 0..=512),
        ]
    }

    fn invalid_hex_byte_strategy() -> impl Strategy<Value = u8> {
        prop_oneof![
            prop::sample::select(vec![
                b'g', b'h', b'z', b'G', b'Z', b':', b'@', b'/', b' ', b'\n', b'\t',
            ]),
            (b'g'..=b'z'),
            (b'G'..=b'Z'),
            (0x20_u8..=0x2f),
            (0x3a_u8..=0x40),
            (0x5b_u8..=0x60),
            (0x7b_u8..=0x7e),
        ]
    }

    proptest! {
        #![proptest_config(proptest_config(1024))]

        #[test]
        fn hex_encoding_and_decoding_roundtrip_with_oracle_differential(
            bytes in boundary_bytes_strategy(),
            case_mask in prop::collection::vec(any::<bool>(), 0..=1024),
        ) {
            let lower = hex_encode(&bytes);
            prop_assert_eq!(lower.len(), bytes.len().saturating_mul(2));
            prop_assert!(is_lowercase_hex(&lower));

            let upper = lower.to_uppercase();
            let has_hex_alpha = lower.bytes().any(|b| (b'a'..=b'f').contains(&b));
            if has_hex_alpha {
                prop_assert!(!is_lowercase_hex(&upper));
            }

            let mixed: String = lower
                .chars()
                .enumerate()
                .map(|(i, ch)| {
                    if case_mask.get(i).copied().unwrap_or(false) {
                        ch.to_ascii_uppercase()
                    } else {
                        ch
                    }
                })
                .collect();

            prop_assert_eq!(hex_decode(&lower), Ok(bytes.clone()));
            prop_assert_eq!(hex_decode(&upper), Ok(bytes.clone()));
            prop_assert_eq!(hex_decode(&mixed), Ok(bytes.clone()));

            let lower_oracle = <Vec<u8> as bitcoin::hex::FromHex>::from_hex(&lower).ok();
            prop_assert_eq!(lower_oracle, Some(bytes.clone()));
            let upper_oracle = <Vec<u8> as bitcoin::hex::FromHex>::from_hex(&upper).ok();
            prop_assert_eq!(upper_oracle, Some(bytes.clone()));
            let mixed_oracle = <Vec<u8> as bitcoin::hex::FromHex>::from_hex(&mixed).ok();
            prop_assert_eq!(mixed_oracle, Some(bytes.clone()));

            if bytes.len() == 32 {
                let mut expected_arr = [0u8; 32];
                expected_arr.copy_from_slice(&bytes);
                prop_assert_eq!(hex_decode_array::<32>(&lower), Ok(expected_arr));
                prop_assert_eq!(hex_decode_array::<32>(&upper), Ok(expected_arr));
                prop_assert_eq!(hex_decode_array::<32>(&mixed), Ok(expected_arr));
            } else {
                let expected_err = HexError::WrongLength {
                    expected: 64,
                    got: bytes.len().saturating_mul(2),
                };
                prop_assert_eq!(hex_decode_array::<32>(&lower), Err(expected_err));
            }
        }

        #[test]
        fn hex_odd_length_refusals(
            bytes in boundary_bytes_strategy(),
        ) {
            let mut odd_hex = hex_encode(&bytes);
            odd_hex.push('a');
            prop_assert_eq!(hex_decode(&odd_hex), Err(HexError::OddLength));
            prop_assert_eq!(
                hex_decode_array::<32>(&odd_hex),
                Err(HexError::WrongLength {
                    expected: 64,
                    got: odd_hex.len(),
                })
            );
        }

        #[test]
        fn hex_invalid_digit_refusals_with_exact_offset(
            bytes in prop::collection::vec(any::<u8>(), 1..=128),
            offset_ratio in 0u32..=1000u32,
            bad_byte in invalid_hex_byte_strategy(),
        ) {
            let valid_hex = hex_encode(&bytes);
            let hex_len = valid_hex.len();
            let max_idx = hex_len.saturating_sub(1);
            let target_offset = (max_idx * usize::try_from(offset_ratio).unwrap_or(0)) / 1000;
            let mut corrupted_bytes = valid_hex.into_bytes();
            corrupted_bytes[target_offset] = bad_byte;
            let Ok(corrupted) = String::from_utf8(corrupted_bytes) else {
                prop_assert!(false, "ASCII corrupted string");
                return Ok(());
            };

            prop_assert_eq!(
                hex_decode(&corrupted),
                Err(HexError::InvalidDigit {
                    offset: target_offset,
                })
            );
        }
    }

    #[test]
    fn hex_decode_array_two_byte_instantiation_decodes_and_refuses() {
        assert_eq!(hex_decode_array::<2>("dead"), Ok([0xde, 0xad]));
        assert_eq!(
            hex_decode_array::<2>("deadbeef"),
            Err(HexError::WrongLength {
                expected: 4,
                got: 8,
            })
        );
    }
}
