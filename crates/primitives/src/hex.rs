//! Hexadecimal text: one encoder and one decoder for the whole workspace.

/// Why a hexadecimal string was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum HexError {
    #[error("hex string has an odd length")]
    OddLength,
    #[error("hex string has an invalid digit at offset {offset}")]
    InvalidDigit { offset: usize },
    #[error("hex string has {got} digits, expected {expected}")]
    WrongLength { expected: usize, got: usize },
}

/// Lowercase hexadecimal text of `bytes`.
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

/// Value of one hexadecimal digit of either case.
#[must_use]
pub const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Whether every character is a digit or a lowercase `a` to `f`.
#[must_use]
pub fn is_lowercase_hex(text: &str) -> bool {
    text.bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Decodes a hexadecimal string of either case.
///
/// # Errors
///
/// Fails on an odd length or a character that is not a hexadecimal digit.
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

/// Decodes exactly `N` bytes from a hexadecimal string of either case.
///
/// # Errors
///
/// Fails on a length other than `2 * N` or a character that is not a hexadecimal digit.
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

    proptest! {
        #[test]
        fn decoding_inverts_encoding_and_matches_rust_bitcoin(
            bytes in proptest::collection::vec(any::<u8>(), 0..64)
        ) {
            let text = hex_encode(&bytes);
            prop_assert!(is_lowercase_hex(&text));
            prop_assert_eq!(hex_decode(&text), Ok(bytes.clone()));
            prop_assert_eq!(hex_decode(&text.to_uppercase()), Ok(bytes.clone()));
            let oracle = <Vec<u8> as bitcoin::hex::FromHex>::from_hex(&text).ok();
            prop_assert_eq!(oracle, Some(bytes));
        }
    }

    #[test]
    fn refusals_name_their_cause_and_offset() {
        assert_eq!(hex_decode("abc"), Err(HexError::OddLength));
        assert_eq!(hex_decode("0g"), Err(HexError::InvalidDigit { offset: 1 }));
        assert_eq!(
            hex_decode_array::<2>("00"),
            Err(HexError::WrongLength {
                expected: 4,
                got: 2
            })
        );
        assert_eq!(hex_decode_array::<2>("00ff"), Ok([0x00, 0xff]));
        assert!(!is_lowercase_hex("00FF"));
    }
}
