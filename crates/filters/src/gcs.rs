use bitcoin_rs_primitives::{Hash256, varint};
use thiserror::Error;

/// BIP158 Golomb-Rice coding parameter for basic block filters.
pub const P: u8 = 19;
/// BIP158 inverse false-positive rate for basic block filters.
pub const M: u64 = 784_931;

/// Errors returned while decoding a Golomb-coded set.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum GcsError {
    /// The compact-size element count is malformed.
    #[error(transparent)]
    Varint(#[from] varint::VarintError),
    /// BIP158 filters are bounded to a 32-bit element count.
    #[error("GCS element count exceeds u32: {0}")]
    CountTooLarge(u64),
    /// The encoded bitstream ended before the next Golomb-Rice code was complete.
    #[error("truncated GCS bitstream")]
    Truncated,
    /// Decoded deltas do not fit in u64.
    #[error("GCS delta overflow")]
    DeltaOverflow,
    /// Bytes remain after decoding exactly the advertised element count.
    #[error("GCS encoding contains excess data")]
    ExcessData,
}

/// Derives the BIP158 `SipHash` key from the first 16 little-endian block-hash bytes.
#[must_use]
pub fn key_from_block_hash(block_hash: Hash256) -> [u8; 16] {
    let bytes = block_hash.to_le_bytes();
    let mut key = [0_u8; 16];
    key.copy_from_slice(&bytes[..16]);
    key
}

/// Hashes raw filter elements into the BIP158 range for the set size.
#[must_use]
pub fn hash_elements(elements: &[Vec<u8>], key: [u8; 16]) -> Vec<u64> {
    let range = u64::try_from(elements.len())
        .unwrap_or_else(|_| unreachable!("usize fits into u64 on supported targets"))
        .saturating_mul(M);
    let mut values = elements
        .iter()
        .map(|element| hash_to_range(element, key, range))
        .collect::<Vec<_>>();
    values.sort_unstable();
    values.dedup();
    values
}

/// Encodes sorted or unsorted hashed GCS values as a BIP158 byte stream.
///
/// `key` is accepted to keep the public API aligned with callers that derive the
/// values from a block-specific key; encoded deltas themselves do not depend on it.
#[must_use]
pub fn encode(items: &[u64], _key: [u8; 16]) -> Vec<u8> {
    let mut values = items.to_vec();
    values.sort_unstable();
    values.dedup();

    let count = u64::try_from(values.len())
        .unwrap_or_else(|_| unreachable!("usize fits into u64 on supported targets"));
    let mut out = varint::encode(count).to_vec();
    let mut writer = BitWriter::new(&mut out);
    let mut last = 0_u64;
    for value in values {
        let delta = value - last;
        writer.write_golomb_rice(delta);
        last = value;
    }
    writer.flush();
    out
}

/// Decodes a BIP158 byte stream into sorted hashed GCS values.
pub fn decode(bytes: &[u8], _key: [u8; 16]) -> Result<Vec<u64>, GcsError> {
    let (count, offset) = varint::decode(bytes)?;
    if count > u64::from(u32::MAX) {
        return Err(GcsError::CountTooLarge(count));
    }
    let capacity = usize::try_from(count).unwrap_or_else(|_| unreachable!("u32 fits into usize"));
    let mut reader = BitReader::new(&bytes[offset..]);
    let mut values = Vec::with_capacity(capacity);
    let mut last = 0_u64;
    for _ in 0..count {
        let delta = reader.read_golomb_rice()?;
        last = last.checked_add(delta).ok_or(GcsError::DeltaOverflow)?;
        values.push(last);
    }
    if !reader.is_at_byte_end() {
        return Err(GcsError::ExcessData);
    }
    Ok(values)
}

/// Tests whether a BIP158 filter may match any target.
pub fn matches(filter: &[u8], key: [u8; 16], targets: &[Vec<u8>]) -> Result<bool, GcsError> {
    let values = decode(filter, key)?;
    if values.is_empty() || targets.is_empty() {
        return Ok(false);
    }

    let range = u64::try_from(values.len())
        .unwrap_or_else(|_| unreachable!("usize fits into u64 on supported targets"))
        .saturating_mul(M);
    let mut queries = targets
        .iter()
        .map(|target| hash_to_range(target, key, range))
        .collect::<Vec<_>>();
    queries.sort_unstable();
    queries.dedup();

    Ok(intersects_sorted(&values, &queries))
}

#[must_use]
fn hash_to_range(element: &[u8], key: [u8; 16], range: u64) -> u64 {
    if range == 0 {
        return 0;
    }
    let k0 = u64::from_le_bytes(
        key[..8]
            .try_into()
            .unwrap_or_else(|_| unreachable_key_width()),
    );
    let k1 = u64::from_le_bytes(
        key[8..]
            .try_into()
            .unwrap_or_else(|_| unreachable_key_width()),
    );
    fast_range64(siphash24(k0, k1, element), range)
}

fn unreachable_key_width() -> ! {
    unreachable!("fixed key slices are exactly eight bytes")
}

#[must_use]
fn fast_range64(value: u64, range: u64) -> u64 {
    let reduced = (u128::from(value) * u128::from(range)) >> 64;
    u64::try_from(reduced).unwrap_or_else(|_| unreachable!("upper half of u64*u64 fits u64"))
}

#[must_use]
fn intersects_sorted(left: &[u64], right: &[u64]) -> bool {
    let mut left_index = 0_usize;
    let mut right_index = 0_usize;
    while let (Some(left_value), Some(right_value)) = (left.get(left_index), right.get(right_index))
    {
        match left_value.cmp(right_value) {
            core::cmp::Ordering::Less => left_index += 1,
            core::cmp::Ordering::Equal => return true,
            core::cmp::Ordering::Greater => right_index += 1,
        }
    }
    false
}

struct BitWriter<'a> {
    out: &'a mut Vec<u8>,
    buffer: u8,
    offset: u8,
}

impl<'a> BitWriter<'a> {
    fn new(out: &'a mut Vec<u8>) -> Self {
        Self {
            out,
            buffer: 0,
            offset: 0,
        }
    }

    fn write_golomb_rice(&mut self, value: u64) {
        let mut quotient = value >> P;
        while quotient > 0 {
            let bits = quotient.min(64);
            let nbits =
                u8::try_from(bits).unwrap_or_else(|_| unreachable!("min bounds bits to 64"));
            self.write_bits(u64::MAX, nbits);
            quotient -= bits;
        }
        self.write_bits(0, 1);
        self.write_bits(value, P);
    }

    fn write_bits(&mut self, data: u64, mut nbits: u8) {
        while nbits > 0 {
            let available = 8 - self.offset;
            let bits = available.min(nbits);
            let shift = nbits - bits;
            let mask = (1_u64 << bits) - 1;
            let chunk = u8::try_from((data >> shift) & mask)
                .unwrap_or_else(|_| unreachable!("at most eight bits fit into u8"));
            self.buffer |= chunk << (available - bits);
            self.offset += bits;
            nbits -= bits;
            if self.offset == 8 {
                self.flush();
            }
        }
    }

    fn flush(&mut self) {
        if self.offset == 0 {
            return;
        }
        self.out.push(self.buffer);
        self.buffer = 0;
        self.offset = 0;
    }
}

struct BitReader<'a> {
    bytes: &'a [u8],
    index: usize,
    offset: u8,
}

impl<'a> BitReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            index: 0,
            offset: 8,
        }
    }

    fn read_golomb_rice(&mut self) -> Result<u64, GcsError> {
        let mut quotient = 0_u64;
        while self.read_bits(1)? == 1 {
            quotient = quotient.checked_add(1).ok_or(GcsError::DeltaOverflow)?;
        }
        let remainder = self.read_bits(P)?;
        quotient
            .checked_shl(u32::from(P))
            .and_then(|base| base.checked_add(remainder))
            .ok_or(GcsError::DeltaOverflow)
    }

    fn read_bits(&mut self, mut nbits: u8) -> Result<u64, GcsError> {
        let mut data = 0_u64;
        while nbits > 0 {
            if self.offset == 8 {
                if self.index == self.bytes.len() {
                    return Err(GcsError::Truncated);
                }
                self.offset = 0;
                self.index += 1;
            }

            let available = 8 - self.offset;
            let bits = available.min(nbits);
            let byte = self.bytes[self.index - 1];
            let chunk = u64::from((byte << self.offset) >> (8 - bits));
            data = (data << bits) | chunk;
            self.offset += bits;
            nbits -= bits;
        }
        Ok(data)
    }

    const fn is_at_byte_end(&self) -> bool {
        self.index == self.bytes.len()
    }
}

#[must_use]
fn siphash24(k0: u64, k1: u64, data: &[u8]) -> u64 {
    let mut state = SipState::new(k0, k1);
    let mut tmp = 0_u64;
    let mut count = 0_u8;

    for byte in data {
        tmp |= u64::from(*byte) << (8 * u32::from(count % 8));
        count = count.wrapping_add(1);
        if count.trailing_zeros() >= 3 {
            state.compress(tmp);
            tmp = 0;
        }
    }

    state.finalize(tmp | (u64::from(count) << 56))
}

struct SipState {
    v0: u64,
    v1: u64,
    v2: u64,
    v3: u64,
}

impl SipState {
    const fn new(k0: u64, k1: u64) -> Self {
        Self {
            v0: 0x736f_6d65_7073_6575 ^ k0,
            v1: 0x646f_7261_6e64_6f6d ^ k1,
            v2: 0x6c79_6765_6e65_7261 ^ k0,
            v3: 0x7465_6462_7974_6573 ^ k1,
        }
    }

    fn compress(&mut self, word: u64) {
        self.v3 ^= word;
        self.round();
        self.round();
        self.v0 ^= word;
    }

    fn finalize(mut self, word: u64) -> u64 {
        self.compress(word);
        self.v2 ^= 0xff;
        self.round();
        self.round();
        self.round();
        self.round();
        self.v0 ^ self.v1 ^ self.v2 ^ self.v3
    }

    fn round(&mut self) {
        self.v0 = self.v0.wrapping_add(self.v1);
        self.v1 = self.v1.rotate_left(13);
        self.v1 ^= self.v0;
        self.v0 = self.v0.rotate_left(32);
        self.v2 = self.v2.wrapping_add(self.v3);
        self.v3 = self.v3.rotate_left(16);
        self.v3 ^= self.v2;
        self.v0 = self.v0.wrapping_add(self.v3);
        self.v3 = self.v3.rotate_left(21);
        self.v3 ^= self.v0;
        self.v2 = self.v2.wrapping_add(self.v1);
        self.v1 = self.v1.rotate_left(17);
        self.v1 ^= self.v2;
        self.v2 = self.v2.rotate_left(32);
    }
}

#[cfg(test)]
mod tests {
    use super::{decode, encode, matches};

    #[test]
    fn matching_hashes_targets_with_filter_range() -> Result<(), Box<dyn std::error::Error>> {
        let key = [7_u8; 16];
        let targets = vec![b"needle".to_vec()];
        let values = super::hash_elements(&targets, key);
        let filter = encode(&values, key);

        assert!(matches(&filter, key, &targets)?);
        assert!(!matches(&filter, key, &[b"absent".to_vec()])?);
        Ok(())
    }

    #[test]
    fn rejects_excess_bytes() {
        let encoded = encode(&[1, 2, 3], [0; 16]);
        let mut with_extra = encoded;
        with_extra.push(0);

        assert!(decode(&with_extra, [0; 16]).is_err());
    }
}
