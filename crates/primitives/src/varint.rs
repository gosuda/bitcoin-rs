use thiserror::Error;
use tinyvec::ArrayVec;

/// Errors returned by Bitcoin compact-size integer decoding.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum VarintError {
    /// The buffer ends before the encoded integer is complete.
    #[error(
        "compact-size varint truncated after prefix {prefix:#04x}; need {needed} bytes, got {available}"
    )]
    Truncated {
        /// Prefix byte that selected the integer width.
        prefix: u8,
        /// Required total encoded bytes.
        needed: usize,
        /// Available total encoded bytes.
        available: usize,
    },
    /// The integer used a wider encoding than consensus permits for its value.
    #[error("non-canonical compact-size varint encoding for {value}")]
    NonCanonical {
        /// Decoded value.
        value: u64,
    },
}

/// Decodes a Bitcoin compact-size integer and returns `(value, bytes_consumed)`.
pub fn decode(buf: &[u8]) -> Result<(u64, usize), VarintError> {
    let Some((&prefix, rest)) = buf.split_first() else {
        return Err(VarintError::Truncated {
            prefix: 0,
            needed: 1,
            available: 0,
        });
    };

    match prefix {
        0x00..=0xfc => Ok((u64::from(prefix), 1)),
        0xfd => {
            let bytes = read_array::<2>(prefix, rest, buf.len())?;
            let value = u64::from(u16::from_le_bytes(bytes));
            if value < 0xfd {
                return Err(VarintError::NonCanonical { value });
            }
            Ok((value, 3))
        }
        0xfe => {
            let bytes = read_array::<4>(prefix, rest, buf.len())?;
            let value = u64::from(u32::from_le_bytes(bytes));
            if value <= 0xffff {
                return Err(VarintError::NonCanonical { value });
            }
            Ok((value, 5))
        }
        0xff => {
            let bytes = read_array::<8>(prefix, rest, buf.len())?;
            let value = u64::from_le_bytes(bytes);
            if value <= 0xffff_ffff {
                return Err(VarintError::NonCanonical { value });
            }
            Ok((value, 9))
        }
    }
}

/// Byte length of the canonical compact-size encoding of `value`.
#[must_use]
pub const fn encoded_len(value: u64) -> usize {
    if value <= 0xfc {
        1
    } else if value <= 0xffff {
        3
    } else if value <= 0xffff_ffff {
        5
    } else {
        9
    }
}

/// Encodes a Bitcoin compact-size integer into a stack-backed buffer.
#[must_use]
pub fn encode(value: u64) -> ArrayVec<[u8; 9]> {
    let mut out = ArrayVec::new();
    if value <= 0xfc {
        out.push(u8::try_from(value).unwrap_or_else(|_| unreachable_small_value()));
    } else if value <= 0xffff {
        out.push(0xfd);
        out.extend_from_slice(
            &u16::try_from(value)
                .unwrap_or_else(|_| unreachable_small_value())
                .to_le_bytes(),
        );
    } else if value <= 0xffff_ffff {
        out.push(0xfe);
        out.extend_from_slice(
            &u32::try_from(value)
                .unwrap_or_else(|_| unreachable_small_value())
                .to_le_bytes(),
        );
    } else {
        out.push(0xff);
        out.extend_from_slice(&value.to_le_bytes());
    }
    out
}

fn read_array<const N: usize>(
    prefix: u8,
    rest: &[u8],
    available: usize,
) -> Result<[u8; N], VarintError> {
    if rest.len() < N {
        return Err(VarintError::Truncated {
            prefix,
            needed: N + 1,
            available,
        });
    }
    let mut out = [0_u8; N];
    out.copy_from_slice(&rest[..N]);
    Ok(out)
}

fn unreachable_small_value() -> ! {
    unreachable!("compact-size branch bounds guarantee integer width")
}

#[cfg(test)]
mod tests {
    use super::{VarintError, decode, encode, encoded_len};

    #[test]
    fn boundary_encodings_are_canonical() -> Result<(), VarintError> {
        let cases: &[(u64, &[u8])] = &[
            (0, &[0x00]),
            (0xfc, &[0xfc]),
            (0xfd, &[0xfd, 0xfd, 0x00]),
            (0xffff, &[0xfd, 0xff, 0xff]),
            (0x1_0000, &[0xfe, 0x00, 0x00, 0x01, 0x00]),
            (0xffff_ffff, &[0xfe, 0xff, 0xff, 0xff, 0xff]),
            (
                0x1_0000_0000,
                &[0xff, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00],
            ),
            (
                u64::MAX,
                &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            ),
        ];

        for (value, bytes) in cases {
            assert_eq!(encode(*value).as_slice(), *bytes);
            assert_eq!(decode(bytes)?, (*value, bytes.len()));
            assert_eq!(encoded_len(*value), bytes.len());
        }
        Ok(())
    }

    #[test]
    fn rejects_truncated_and_noncanonical_encodings() {
        assert_eq!(
            decode(&[0xfd, 0x01]),
            Err(VarintError::Truncated {
                prefix: 0xfd,
                needed: 3,
                available: 2
            })
        );
        assert_eq!(
            decode(&[0xfd, 0xfc, 0x00]),
            Err(VarintError::NonCanonical { value: 0xfc })
        );
        assert_eq!(
            decode(&[0xfe, 0xff, 0xff, 0x00, 0x00]),
            Err(VarintError::NonCanonical { value: 0xffff })
        );
        assert_eq!(
            decode(&[0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00]),
            Err(VarintError::NonCanonical { value: 0xffff_ffff })
        );
    }
}
