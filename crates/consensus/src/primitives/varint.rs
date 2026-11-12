use thiserror::Error;
use tinyvec::ArrayVec;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum VarintError {
    #[error(
        "compact-size varint truncated after prefix {prefix:#04x}; need {needed} bytes, got {available}"
    )]
    Truncated {
        prefix: u8,
        needed: usize,
        available: usize,
    },
    #[error("non-canonical compact-size varint encoding for {value}")]
    NonCanonical { value: u64 },
}

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

#[must_use]
pub fn encode(value: u64) -> ArrayVec<[u8; 9]> {
    let mut buf = [0_u8; 9];
    let len = encode_into(value, &mut buf);
    let mut out = ArrayVec::new();
    out.extend_from_slice(&buf[..len]);
    out
}

#[must_use]
pub fn encode_into(value: u64, out: &mut [u8; 9]) -> usize {
    let payload = value.to_le_bytes();
    if value <= 0xfc {
        out[0] = payload[0];
        1
    } else if value <= 0xffff {
        out[0] = 0xfd;
        out[1] = payload[0];
        out[2] = payload[1];
        3
    } else if value <= 0xffff_ffff {
        out[0] = 0xfe;
        out[1] = payload[0];
        out[2] = payload[1];
        out[3] = payload[2];
        out[4] = payload[3];
        5
    } else {
        out[0] = 0xff;
        out[1] = payload[0];
        out[2] = payload[1];
        out[3] = payload[2];
        out[4] = payload[3];
        out[5] = payload[4];
        out[6] = payload[5];
        out[7] = payload[6];
        out[8] = payload[7];
        9
    }
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

#[cfg(kani)]
mod proofs;

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
