use core::fmt;

use bytemuck::{Pod, Zeroable};
use thiserror::Error;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

/// A 256-bit Bitcoin hash stored in consensus little-endian byte order.
#[derive(
    Copy,
    Clone,
    Debug,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Zeroable,
    Pod,
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
    Unaligned,
)]
#[repr(transparent)]
pub struct Hash256([u8; 32]);

/// Errors returned while parsing a big-endian hash string.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum HashError {
    /// The input is not exactly 64 hexadecimal characters.
    #[error("hash hex must be 64 characters, got {0}")]
    InvalidLength(usize),
    /// A byte contains a non-hexadecimal character.
    #[error("invalid hex at byte offset {offset}: {byte:#04x}")]
    InvalidHex {
        /// Offset of the invalid byte.
        offset: usize,
        /// The invalid byte.
        byte: u8,
    },
}

impl Hash256 {
    /// Constructs a hash from consensus little-endian bytes.
    #[must_use]
    pub const fn from_le_bytes(bytes: &[u8; 32]) -> Self {
        Self(*bytes)
    }

    /// Returns the consensus little-endian bytes.
    #[must_use]
    pub const fn to_le_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Parses a conventional big-endian lowercase or uppercase hexadecimal hash.
    pub fn from_str_be(s: &str) -> Result<Self, HashError> {
        let bytes = s.as_bytes();
        if bytes.len() != 64 {
            return Err(HashError::InvalidLength(bytes.len()));
        }

        let mut out = [0_u8; 32];
        let mut i = 0;
        while i < 32 {
            let hi_offset = i * 2;
            let lo_offset = hi_offset + 1;
            let hi = decode_nibble(bytes[hi_offset], hi_offset)?;
            let lo = decode_nibble(bytes[lo_offset], lo_offset)?;
            out[31 - i] = (hi << 4) | lo;
            i += 1;
        }
        Ok(Self(out))
    }

    /// Formats this hash as conventional big-endian lowercase hexadecimal.
    #[must_use]
    pub fn to_string_be(self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut s = String::with_capacity(64);
        for byte in self.0.iter().rev() {
            s.push(char::from(HEX[usize::from(byte >> 4)]));
            s.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        s
    }

    /// Returns the backing little-endian byte array.
    #[must_use]
    pub const fn as_byte_array(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns the first eight bytes of the little-endian representation.
    #[must_use]
    pub fn prefix8(self) -> [u8; 8] {
        let mut prefix = [0_u8; 8];
        prefix.copy_from_slice(&self.0[..8]);
        prefix
    }
}

impl fmt::Display for Hash256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0.iter().rev() {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl core::str::FromStr for Hash256 {
    type Err = HashError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_str_be(s)
    }
}

const fn decode_nibble(byte: u8, offset: usize) -> Result<u8, HashError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(HashError::InvalidHex { offset, byte }),
    }
}

#[cfg(test)]
mod tests {
    use super::{Hash256, HashError};

    #[test]
    fn parses_and_formats_big_endian_hex() -> Result<(), HashError> {
        let hash = Hash256::from_str_be(
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
        )?;

        assert_eq!(
            hash.to_le_bytes(),
            [
                0x6f, 0xe2, 0x8c, 0x0a, 0xb6, 0xf1, 0xb3, 0x72, 0xc1, 0xa6, 0xa2, 0x46, 0xae, 0x63,
                0xf7, 0x4f, 0x93, 0x1e, 0x83, 0x65, 0xe1, 0x5a, 0x08, 0x9c, 0x68, 0xd6, 0x19, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ]
        );
        assert_eq!(
            hash.to_string_be(),
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
        );
        assert_eq!(
            hash.prefix8(),
            [0x6f, 0xe2, 0x8c, 0x0a, 0xb6, 0xf1, 0xb3, 0x72]
        );
        Ok(())
    }

    #[test]
    fn rejects_bad_hex() {
        assert_eq!(Hash256::from_str_be("00"), Err(HashError::InvalidLength(2)));
        let bad = "z00000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
        assert_eq!(
            Hash256::from_str_be(bad),
            Err(HashError::InvalidHex {
                offset: 0,
                byte: b'z'
            })
        );
    }
}
