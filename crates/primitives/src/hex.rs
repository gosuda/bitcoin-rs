//! Byte-slice hex codec for wire bytes, digests, logs, and RPC responses.
//!
//! [`crate::hash::Hash256`] displays its bytes in reverse (the Bitcoin
//! convention) through its own `Display`, which shares this module's digit
//! table; that ordering is a distinct convention for a distinct type, not a
//! second codec.

use thiserror::Error;

/// Lowercase hexadecimal digits, indexed by nibble value.
pub(crate) const HEX: &[u8; 16] = b"0123456789abcdef";

/// Encodes `bytes` as lowercase hexadecimal.
#[must_use]
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

/// Why [`hex_decode`] rejected an input string.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum HexDecodeError {
    /// The input has an odd number of characters.
    #[error("hex string has odd length")]
    OddLength,
    /// A byte is not an ASCII hexadecimal digit.
    #[error("invalid hex character")]
    InvalidChar,
}

/// Decodes a lowercase or uppercase hexadecimal string into bytes.
pub fn hex_decode(hex: &str) -> Result<Vec<u8>, HexDecodeError> {
    let bytes = hex.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err(HexDecodeError::OddLength);
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for chunk in bytes.chunks(2) {
        let hi = decode_nibble(chunk[0]).ok_or(HexDecodeError::InvalidChar)?;
        let lo = decode_nibble(chunk[1]).ok_or(HexDecodeError::InvalidChar)?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

const fn decode_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_arbitrary_bytes() {
        let bytes = [0x00, 0x0f, 0xff, 0xab, 0x10];
        assert_eq!(hex_decode(&hex_encode(&bytes)), Ok(bytes.to_vec()));
    }

    #[test]
    fn accepts_uppercase() {
        assert_eq!(hex_decode("AB0f"), Ok(vec![0xab, 0x0f]));
    }

    #[test]
    fn rejects_odd_length() {
        assert_eq!(hex_decode("abc"), Err(HexDecodeError::OddLength));
    }

    #[test]
    fn rejects_invalid_char() {
        assert_eq!(hex_decode("zz"), Err(HexDecodeError::InvalidChar));
    }
}
