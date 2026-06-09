#![allow(clippy::inline_always)] // PERF: Criterion shows forced inlining improves MuHash insert hot paths.

use bitcoin_rs_primitives::Hash256;
use ruint::Uint;
use sha2::{Digest, Sha256};

const BYTE_LEN: usize = 384;
const LIMBS: usize = 48;
const LIMB_BITS: usize = 64;
const MAX_PRIME_DIFF: u64 = 1_103_717;

type U3072 = Uint<3072, LIMBS>;

const MODULUS: U3072 = U3072::from_limbs([
    18_446_744_073_708_447_899,
    u64::MAX,
    u64::MAX,
    u64::MAX,
    u64::MAX,
    u64::MAX,
    u64::MAX,
    u64::MAX,
    u64::MAX,
    u64::MAX,
    u64::MAX,
    u64::MAX,
    u64::MAX,
    u64::MAX,
    u64::MAX,
    u64::MAX,
    u64::MAX,
    u64::MAX,
    u64::MAX,
    u64::MAX,
    u64::MAX,
    u64::MAX,
    u64::MAX,
    u64::MAX,
    u64::MAX,
    u64::MAX,
    u64::MAX,
    u64::MAX,
    u64::MAX,
    u64::MAX,
    u64::MAX,
    u64::MAX,
    u64::MAX,
    u64::MAX,
    u64::MAX,
    u64::MAX,
    u64::MAX,
    u64::MAX,
    u64::MAX,
    u64::MAX,
    u64::MAX,
    u64::MAX,
    u64::MAX,
    u64::MAX,
    u64::MAX,
    u64::MAX,
    u64::MAX,
    u64::MAX,
]);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Num3072 {
    limbs: [u64; LIMBS],
}

impl Num3072 {
    const ONE: Self = {
        let mut limbs = [0_u64; LIMBS];
        limbs[0] = 1;
        Self { limbs }
    };

    fn from_le_bytes(bytes: &[u8; BYTE_LEN]) -> Self {
        let mut limbs = [0_u64; LIMBS];
        for (idx, chunk) in bytes.chunks_exact(8).enumerate() {
            let mut limb = [0_u8; 8];
            limb.copy_from_slice(chunk);
            limbs[idx] = u64::from_le_bytes(limb);
        }
        Self { limbs }
    }

    fn from_be_bytes_reduced(bytes: &[u8; BYTE_LEN]) -> Self {
        let mut little_endian = *bytes;
        little_endian.reverse();
        let mut value = Self::from_le_bytes(&little_endian);
        if value.is_overflow() {
            value.full_reduce();
        }
        value
    }

    fn to_be_bytes_reduced(self) -> [u8; BYTE_LEN] {
        let mut value = self;
        if value.is_overflow() {
            value.full_reduce();
        }
        let mut bytes = value.to_le_bytes();
        bytes.reverse();
        bytes
    }

    fn to_reduced_ruint(self) -> U3072 {
        let mut value = self;
        if value.is_overflow() {
            value.full_reduce();
        }
        U3072::from_le_bytes(value.to_le_bytes())
    }

    fn to_le_bytes(self) -> [u8; BYTE_LEN] {
        let mut out = [0_u8; BYTE_LEN];
        for (chunk, limb) in out.chunks_exact_mut(8).zip(self.limbs) {
            chunk.copy_from_slice(&limb.to_le_bytes());
        }
        out
    }

    #[inline(always)]
    fn multiply(&mut self, other: &Self) {
        let left = self.limbs;
        let right = &other.limbs;
        let mut tmp = [0_u64; LIMBS];
        let mut c0 = 0_u64;
        let mut c1 = 0_u64;
        let mut c2 = 0_u64;

        for j in 0..LIMBS - 1 {
            let mut d0 = 0_u64;
            let mut d1 = 0_u64;
            let mut d2 = 0_u64;
            mul_limb(&mut d0, &mut d1, left[j + 1], right[LIMBS - 1]);
            // PERF: split the high-column accumulation into two independent
            // triple-carry chains so the 128-bit multiplies issue without
            // waiting on the carry chain of the previous `muladd3`. Both chains
            // sum a disjoint subset of the same products and are merged before
            // the column total is consumed, so the 192-bit column value is
            // byte-identical to the serial accumulation: integer addition is
            // associative/commutative and every partial sum is bounded by the
            // full column total, which the original algorithm keeps < 2^192.
            let mut e0 = 0_u64;
            let mut e1 = 0_u64;
            let mut e2 = 0_u64;
            let mut i = j + 2;
            while i + 1 < LIMBS {
                muladd3(&mut d0, &mut d1, &mut d2, left[i], right[LIMBS + j - i]);
                muladd3(
                    &mut e0,
                    &mut e1,
                    &mut e2,
                    left[i + 1],
                    right[LIMBS + j - i - 1],
                );
                i += 2;
            }
            if i < LIMBS {
                muladd3(&mut d0, &mut d1, &mut d2, left[i], right[LIMBS + j - i]);
            }
            add3(&mut d0, &mut d1, &mut d2, e0, e1, e2);
            mulnadd3(&mut c0, &mut c1, &mut c2, d0, d1, d2, MAX_PRIME_DIFF);

            // PERF: same split for the low-column accumulation. The seed
            // (carry-in plus the `mulnadd3` fold above) stays in the (c0,c1,c2)
            // chain; the second chain (f0,f1,f2) starts at zero and collects the
            // odd-offset products. Merging before `extract3` preserves the exact
            // column total and therefore the emitted limb and carry-out.
            let mut f0 = 0_u64;
            let mut f1 = 0_u64;
            let mut f2 = 0_u64;
            let mut k = 0;
            while k < j {
                muladd3(&mut c0, &mut c1, &mut c2, left[k], right[j - k]);
                muladd3(&mut f0, &mut f1, &mut f2, left[k + 1], right[j - k - 1]);
                k += 2;
            }
            if k <= j {
                muladd3(&mut c0, &mut c1, &mut c2, left[k], right[j - k]);
            }
            add3(&mut c0, &mut c1, &mut c2, f0, f1, f2);
            tmp[j] = extract3(&mut c0, &mut c1, &mut c2);
        }

        debug_assert_eq!(c2, 0);
        let mut g0 = 0_u64;
        let mut g1 = 0_u64;
        let mut g2 = 0_u64;
        let mut i = 0;
        while i + 1 < LIMBS {
            muladd3(&mut c0, &mut c1, &mut c2, left[i], right[LIMBS - 1 - i]);
            muladd3(
                &mut g0,
                &mut g1,
                &mut g2,
                left[i + 1],
                right[LIMBS - 1 - (i + 1)],
            );
            i += 2;
        }
        if i < LIMBS {
            muladd3(&mut c0, &mut c1, &mut c2, left[i], right[LIMBS - 1 - i]);
        }
        add3(&mut c0, &mut c1, &mut c2, g0, g1, g2);
        tmp[LIMBS - 1] = extract3(&mut c0, &mut c1, &mut c2);

        muln2(&mut c0, &mut c1, MAX_PRIME_DIFF);
        for (idx, limb) in tmp.into_iter().enumerate() {
            self.limbs[idx] = addnextract2(&mut c0, &mut c1, limb);
        }

        debug_assert_eq!(c1, 0);
        debug_assert!(c0 == 0 || c0 == 1);

        if self.is_overflow() {
            self.full_reduce();
        }
        if c0 != 0 {
            self.full_reduce();
        }
    }

    #[inline(always)]
    fn is_overflow(&self) -> bool {
        if self.limbs[0] <= u64::MAX - MAX_PRIME_DIFF {
            return false;
        }
        self.limbs[1..].iter().all(|limb| *limb == u64::MAX)
    }

    #[inline(always)]
    fn full_reduce(&mut self) {
        let mut c0 = MAX_PRIME_DIFF;
        let mut c1 = 0_u64;
        for limb in &mut self.limbs {
            *limb = addnextract2(&mut c0, &mut c1, *limb);
        }
    }
}

/// Running 3072-bit `MuHash` accumulator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MuHash3072 {
    numerator: Num3072,
    denominator: Num3072,
}

impl MuHash3072 {
    /// Creates the identity accumulator.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            numerator: Num3072::ONE,
            denominator: Num3072::ONE,
        }
    }

    /// Inserts one byte string into the multiset.
    pub fn insert(&mut self, data: &[u8]) {
        self.numerator.multiply(&element(data));
    }

    /// Removes one byte string from the multiset.
    pub fn remove(&mut self, data: &[u8]) {
        self.denominator.multiply(&element(data));
    }

    /// Combines another accumulator into this accumulator.
    #[inline(always)]
    pub fn combine(&mut self, other: &Self) {
        self.numerator.multiply(&other.numerator);
        self.denominator.multiply(&other.denominator);
    }

    #[inline(always)]
    pub(crate) fn combine_numerator(&mut self, other: &Self) {
        self.numerator.multiply(&other.numerator);
    }

    #[inline(always)]
    pub(crate) fn combine_denominator(&mut self, other: &Self) {
        self.denominator.multiply(&other.denominator);
    }

    /// Finalizes to the 3072-bit group element, serialized big-endian.
    #[must_use]
    pub fn finalize(&self) -> [u8; BYTE_LEN] {
        let denominator = self.denominator.to_reduced_ruint();
        let quotient = match denominator.inv_mod(MODULUS) {
            Some(inverse) => self.numerator.to_reduced_ruint().mul_mod(inverse, MODULUS),
            None => U3072::ZERO,
        };
        quotient.to_be_bytes::<BYTE_LEN>()
    }

    /// Finalizes to Bitcoin Core's 32-byte `MuHash` digest.
    ///
    /// Core hashes the finalized 3072-bit group element in little-endian
    /// byte order, then exposes the resulting `uint256` with `GetHex()`.
    #[must_use]
    pub fn finalize_hash(&self) -> Hash256 {
        let mut element = self.finalize();
        element.reverse();
        let digest: [u8; 32] = Sha256::digest(element).into();
        Hash256::from_le_bytes(&digest)
    }

    pub(crate) fn from_parts(numerator: &[u8; BYTE_LEN], denominator: &[u8; BYTE_LEN]) -> Self {
        Self {
            numerator: Num3072::from_be_bytes_reduced(numerator),
            denominator: Num3072::from_be_bytes_reduced(denominator),
        }
    }

    pub(crate) fn numerator_bytes(&self) -> [u8; BYTE_LEN] {
        self.numerator.to_be_bytes_reduced()
    }

    pub(crate) fn denominator_bytes(&self) -> [u8; BYTE_LEN] {
        self.denominator.to_be_bytes_reduced()
    }
}

impl Default for MuHash3072 {
    fn default() -> Self {
        Self::new()
    }
}

#[inline(always)]
fn element(data: &[u8]) -> Num3072 {
    let key: [u8; 32] = Sha256::digest(data).into();
    let key_words = chacha20_key_words(&key);
    let base_state = chacha20_base_state(&key_words);
    let mut limbs = [0_u64; LIMBS];
    let mut block_counter = 0_u32;
    for limb_block in limbs.chunks_exact_mut(8) {
        write_chacha_block_as_limbs(limb_block, &base_state, block_counter);
        block_counter = block_counter.wrapping_add(1);
    }
    Num3072 { limbs }
}

#[inline(always)]
fn write_chacha_block_as_limbs(limbs: &mut [u64], base_state: &[u32; 16], counter: u32) {
    debug_assert_eq!(limbs.len(), 8);
    let mut state = *base_state;
    state[12] = counter;
    let mut working = state;
    for _ in 0..10 {
        quarter_round(&mut working, 0, 4, 8, 12);
        quarter_round(&mut working, 1, 5, 9, 13);
        quarter_round(&mut working, 2, 6, 10, 14);
        quarter_round(&mut working, 3, 7, 11, 15);
        quarter_round(&mut working, 0, 5, 10, 15);
        quarter_round(&mut working, 1, 6, 11, 12);
        quarter_round(&mut working, 2, 7, 8, 13);
        quarter_round(&mut working, 3, 4, 9, 14);
    }
    limbs[0] = chacha_limb(working[0], state[0], working[1], state[1]);
    limbs[1] = chacha_limb(working[2], state[2], working[3], state[3]);
    limbs[2] = chacha_limb(working[4], state[4], working[5], state[5]);
    limbs[3] = chacha_limb(working[6], state[6], working[7], state[7]);
    limbs[4] = chacha_limb(working[8], state[8], working[9], state[9]);
    limbs[5] = chacha_limb(working[10], state[10], working[11], state[11]);
    limbs[6] = chacha_limb(working[12], state[12], working[13], state[13]);
    limbs[7] = chacha_limb(working[14], state[14], working[15], state[15]);
}

#[inline(always)]
fn chacha_limb(left: u32, left_state: u32, right: u32, right_state: u32) -> u64 {
    let left = left.wrapping_add(left_state);
    let right = right.wrapping_add(right_state);
    u64::from(left) | (u64::from(right) << 32)
}

#[inline(always)]
fn low_u64(value: u128) -> u64 {
    u64::try_from(value & u128::from(u64::MAX)).unwrap_or(u64::MAX)
}

#[inline(always)]
fn high_u64(value: u128) -> u64 {
    u64::try_from(value >> LIMB_BITS).unwrap_or(u64::MAX)
}

#[inline(always)]
fn extract3(c0: &mut u64, c1: &mut u64, c2: &mut u64) -> u64 {
    let limb = *c0;
    *c0 = *c1;
    *c1 = *c2;
    *c2 = 0;
    limb
}

#[inline(always)]
fn mul_limb(c0: &mut u64, c1: &mut u64, left: u64, right: u64) {
    let product = u128::from(left) * u128::from(right);
    *c0 = low_u64(product);
    *c1 = high_u64(product);
}

#[inline(always)]
fn mulnadd3(c0: &mut u64, c1: &mut u64, c2: &mut u64, d0: u64, d1: u64, d2: u64, n: u64) {
    let mut product = u128::from(d0) * u128::from(n) + u128::from(*c0);
    *c0 = low_u64(product);
    product = (product >> LIMB_BITS) + u128::from(d1) * u128::from(n) + u128::from(*c1);
    *c1 = low_u64(product);
    *c2 = low_u64((product >> LIMB_BITS) + u128::from(d2) * u128::from(n));
}

#[inline(always)]
fn muln2(c0: &mut u64, c1: &mut u64, n: u64) {
    let mut product = u128::from(*c0) * u128::from(n);
    *c0 = low_u64(product);
    product = (product >> LIMB_BITS) + u128::from(*c1) * u128::from(n);
    *c1 = low_u64(product);
}

#[inline(always)]
fn add3(c0: &mut u64, c1: &mut u64, c2: &mut u64, b0: u64, b1: u64, b2: u64) {
    let (new_c0, carry0) = c0.overflowing_add(b0);
    *c0 = new_c0;
    let (sum1, carry1a) = c1.overflowing_add(b1);
    let (new_c1, carry1b) = sum1.overflowing_add(u64::from(carry0));
    *c1 = new_c1;
    *c2 = c2
        .wrapping_add(b2)
        .wrapping_add(u64::from(carry1a))
        .wrapping_add(u64::from(carry1b));
}

#[inline(always)]
fn muladd3(c0: &mut u64, c1: &mut u64, c2: &mut u64, left: u64, right: u64) {
    let product = u128::from(left) * u128::from(right);
    let low = low_u64(product);
    let high = high_u64(product);

    let (new_c0, carry0) = c0.overflowing_add(low);
    *c0 = new_c0;
    let high = high.wrapping_add(u64::from(carry0));
    let (new_c1, carry1) = c1.overflowing_add(high);
    *c1 = new_c1;
    *c2 = c2.wrapping_add(u64::from(carry1));
}

#[inline(always)]
fn addnextract2(c0: &mut u64, c1: &mut u64, value: u64) -> u64 {
    let mut c2 = 0_u64;
    let (new_c0, carry) = c0.overflowing_add(value);
    *c0 = new_c0;
    if carry {
        let (new_c1, overflow) = c1.overflowing_add(1);
        *c1 = new_c1;
        if overflow {
            c2 = 1;
        }
    }

    let limb = *c0;
    *c0 = *c1;
    *c1 = c2;
    limb
}

#[cfg(test)]
fn chacha20_keystream(key: &[u8; 32], out: &mut [u8; BYTE_LEN]) {
    let key_words = chacha20_key_words(key);
    let mut block_counter = 0_u32;
    for block in out.chunks_exact_mut(64) {
        let words = chacha20_block_words(&key_words, block_counter);
        chacha20_block(&words, block);
        block_counter = block_counter.wrapping_add(1);
    }
}

#[inline]
fn chacha20_key_words(key: &[u8; 32]) -> [u32; 8] {
    core::array::from_fn(|idx| {
        let offset = idx * 4;
        u32::from_le_bytes([
            key[offset],
            key[offset + 1],
            key[offset + 2],
            key[offset + 3],
        ])
    })
}

#[inline]
fn chacha20_base_state(key_words: &[u32; 8]) -> [u32; 16] {
    [
        0x6170_7865,
        0x3320_646e,
        0x7962_2d32,
        0x6b20_6574,
        key_words[0],
        key_words[1],
        key_words[2],
        key_words[3],
        key_words[4],
        key_words[5],
        key_words[6],
        key_words[7],
        0,
        0,
        0,
        0,
    ]
}

#[cfg(test)]
#[inline]
fn chacha20_block_words(key_words: &[u32; 8], counter: u32) -> [u32; 16] {
    let mut state = chacha20_base_state(key_words);
    state[12] = counter;
    let mut working = state;
    for _ in 0..10 {
        quarter_round(&mut working, 0, 4, 8, 12);
        quarter_round(&mut working, 1, 5, 9, 13);
        quarter_round(&mut working, 2, 6, 10, 14);
        quarter_round(&mut working, 3, 7, 11, 15);
        quarter_round(&mut working, 0, 5, 10, 15);
        quarter_round(&mut working, 1, 6, 11, 12);
        quarter_round(&mut working, 2, 7, 8, 13);
        quarter_round(&mut working, 3, 4, 9, 14);
    }

    working[0] = working[0].wrapping_add(state[0]);
    working[1] = working[1].wrapping_add(state[1]);
    working[2] = working[2].wrapping_add(state[2]);
    working[3] = working[3].wrapping_add(state[3]);
    working[4] = working[4].wrapping_add(state[4]);
    working[5] = working[5].wrapping_add(state[5]);
    working[6] = working[6].wrapping_add(state[6]);
    working[7] = working[7].wrapping_add(state[7]);
    working[8] = working[8].wrapping_add(state[8]);
    working[9] = working[9].wrapping_add(state[9]);
    working[10] = working[10].wrapping_add(state[10]);
    working[11] = working[11].wrapping_add(state[11]);
    working[12] = working[12].wrapping_add(state[12]);
    working[13] = working[13].wrapping_add(state[13]);
    working[14] = working[14].wrapping_add(state[14]);
    working[15] = working[15].wrapping_add(state[15]);
    working
}

#[cfg(test)]
fn chacha20_block(words: &[u32; 16], out: &mut [u8]) {
    for (chunk, word) in out.chunks_exact_mut(4).zip(words) {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
}

#[inline]
const fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(12);
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(7);
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Frozen byte-for-byte copy of the ORIGINAL serial `Num3072::multiply`
    /// (single triple-carry accumulator, no chain splitting). Reuses the
    /// unchanged column helpers (`mul_limb`, `muladd3`, `mulnadd3`, `extract3`,
    /// `muln2`, `addnextract2`, `is_overflow`, `full_reduce`) so it is a genuine
    /// reference for the optimized implementation, not a transform of it.
    fn reference_multiply_into(target: &mut Num3072, other: &Num3072) {
        let left = target.limbs;
        let right = &other.limbs;
        let mut tmp = [0_u64; LIMBS];
        let mut c0 = 0_u64;
        let mut c1 = 0_u64;
        let mut c2 = 0_u64;

        for j in 0..LIMBS - 1 {
            let mut d0 = 0_u64;
            let mut d1 = 0_u64;
            let mut d2 = 0_u64;
            mul_limb(&mut d0, &mut d1, left[j + 1], right[LIMBS - 1]);
            for i in j + 2..LIMBS {
                muladd3(&mut d0, &mut d1, &mut d2, left[i], right[LIMBS + j - i]);
            }
            mulnadd3(&mut c0, &mut c1, &mut c2, d0, d1, d2, MAX_PRIME_DIFF);
            for i in 0..=j {
                muladd3(&mut c0, &mut c1, &mut c2, left[i], right[j - i]);
            }
            tmp[j] = extract3(&mut c0, &mut c1, &mut c2);
        }

        assert_eq!(c2, 0);
        for i in 0..LIMBS {
            muladd3(&mut c0, &mut c1, &mut c2, left[i], right[LIMBS - 1 - i]);
        }
        tmp[LIMBS - 1] = extract3(&mut c0, &mut c1, &mut c2);

        muln2(&mut c0, &mut c1, MAX_PRIME_DIFF);
        for (idx, limb) in tmp.into_iter().enumerate() {
            target.limbs[idx] = addnextract2(&mut c0, &mut c1, limb);
        }

        assert_eq!(c1, 0);
        assert!(c0 == 0 || c0 == 1);

        if target.is_overflow() {
            target.full_reduce();
        }
        if c0 != 0 {
            target.full_reduce();
        }
    }

    /// Deterministic 64-bit splitmix PRNG: zero-dependency, reproducible seed
    /// expansion for the `>=100_000` random differential vectors.
    struct SplitMix64(u64);

    impl SplitMix64 {
        const fn new(seed: u64) -> Self {
            Self(seed)
        }

        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        }

        fn fill_limbs(&mut self) -> [u64; LIMBS] {
            core::array::from_fn(|_| self.next_u64())
        }
    }

    /// Adversarial single-limb fillers for carry/boundary coverage.
    fn boundary_limb_patterns() -> Vec<[u64; LIMBS]> {
        let all_max = [u64::MAX; LIMBS];
        let all_zero = [0_u64; LIMBS];
        let all_one = [1_u64; LIMBS];
        let alternating_hi = core::array::from_fn(|i| if i % 2 == 0 { u64::MAX } else { 0 });
        let alternating_lo = core::array::from_fn(|i| if i % 2 == 0 { 0 } else { u64::MAX });

        let mut modulus_low = [u64::MAX; LIMBS];
        modulus_low[0] = u64::MAX - MAX_PRIME_DIFF;
        let mut modulus_minus_one = [u64::MAX; LIMBS];
        modulus_minus_one[0] = u64::MAX - MAX_PRIME_DIFF - 1;
        let mut modulus_plus_one = [u64::MAX; LIMBS];
        modulus_plus_one[0] = u64::MAX - MAX_PRIME_DIFF + 1;

        let single_high = core::array::from_fn(|i| if i == LIMBS - 1 { u64::MAX } else { 0 });
        let single_low_bit = {
            let mut limbs = [0_u64; LIMBS];
            limbs[0] = 1;
            limbs
        };
        let single_high_bit = {
            let mut limbs = [0_u64; LIMBS];
            limbs[LIMBS - 1] = 1 << 63;
            limbs
        };
        let carry_chain = core::array::from_fn(|i| if i == 0 { u64::MAX } else { 1 });

        vec![
            all_max,
            all_zero,
            all_one,
            alternating_hi,
            alternating_lo,
            modulus_low,
            modulus_minus_one,
            modulus_plus_one,
            single_high,
            single_low_bit,
            single_high_bit,
            carry_chain,
        ]
    }

    /// Asserts the optimized `multiply` produces RAW limbs (pre-`to_reduced_ruint`)
    /// byte-identical to the frozen serial reference for one input pair.
    fn assert_multiply_byte_identical(left: &[u64; LIMBS], right: &[u64; LIMBS]) {
        let mut optimized = Num3072 { limbs: *left };
        optimized.multiply(&Num3072 { limbs: *right });

        let mut reference = Num3072 { limbs: *left };
        reference_multiply_into(&mut reference, &Num3072 { limbs: *right });

        assert_eq!(
            optimized.limbs, reference.limbs,
            "raw limbs diverged for left={left:?} right={right:?}"
        );
    }

    #[test]
    fn multiply_byte_identical_on_boundary_patterns() {
        let patterns = boundary_limb_patterns();
        for left in &patterns {
            for right in &patterns {
                assert_multiply_byte_identical(left, right);
            }
        }
    }

    #[test]
    fn multiply_byte_identical_on_seeded_random_inputs() {
        const ITERATIONS: usize = 120_000;
        let mut rng = SplitMix64::new(0x6d75_6861_7368_3372);
        for _ in 0..ITERATIONS {
            let left = rng.fill_limbs();
            let right = rng.fill_limbs();
            assert_multiply_byte_identical(&left, &right);
        }
    }

    #[test]
    fn multiply_byte_identical_on_random_chains() {
        // Exercises the unreduced-state propagation the bench hot loop relies on:
        // repeated multiply without an intervening normalization. 4_000 chains of
        // length 8 = 32_000 chained multiplies compared limb-for-limb.
        const CHAINS: usize = 4_000;
        const CHAIN_LEN: usize = 8;
        let mut rng = SplitMix64::new(0x4d75_4861_7368_4368);
        for _ in 0..CHAINS {
            let start = rng.fill_limbs();
            let mut optimized = Num3072 { limbs: start };
            let mut reference = Num3072 { limbs: start };
            for _ in 0..CHAIN_LEN {
                let factor = rng.fill_limbs();
                optimized.multiply(&Num3072 { limbs: factor });
                reference_multiply_into(&mut reference, &Num3072 { limbs: factor });
                assert_eq!(
                    optimized.limbs, reference.limbs,
                    "raw limbs diverged mid-chain for factor={factor:?}"
                );
            }
        }
    }

    #[test]
    fn finalize_byte_identical_after_optimized_multiply_chain() {
        // Confirms the optimized path also matches the ruint oracle through
        // finalize() across a seeded operation chain.
        let mut rng = SplitMix64::new(0xf1_0a11_2e57_3072);
        for _ in 0..2_000 {
            let mut candidate = MuHash3072::new();
            let mut reference = ReferenceMuHash3072::new();
            for _ in 0..6 {
                let len = usize::try_from(rng.next_u64() % 48).unwrap_or(0);
                let data: Vec<u8> = (0..len)
                    .map(|_| u8::try_from(rng.next_u64() & 0xff).unwrap_or(0))
                    .collect();
                if rng.next_u64() & 1 == 0 {
                    candidate.insert(&data);
                    reference.insert(&data);
                } else {
                    candidate.remove(&data);
                    reference.remove(&data);
                }
            }
            assert_eq!(candidate.finalize(), reference.finalize());
            assert_eq!(candidate.finalize_hash(), reference.finalize_hash());
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct ReferenceMuHash3072 {
        numerator: U3072,
        denominator: U3072,
    }

    impl ReferenceMuHash3072 {
        const fn new() -> Self {
            Self {
                numerator: U3072::ONE,
                denominator: U3072::ONE,
            }
        }

        fn from_parts(numerator: &[u8; BYTE_LEN], denominator: &[u8; BYTE_LEN]) -> Self {
            Self {
                numerator: reference_reduce(&U3072::from_be_bytes(*numerator)),
                denominator: reference_reduce(&U3072::from_be_bytes(*denominator)),
            }
        }

        fn insert(&mut self, data: &[u8]) {
            self.numerator = reference_mul(&self.numerator, &reference_element(data));
        }

        fn remove(&mut self, data: &[u8]) {
            self.denominator = reference_mul(&self.denominator, &reference_element(data));
        }

        fn combine(&mut self, other: &Self) {
            self.numerator = reference_mul(&self.numerator, &other.numerator);
            self.denominator = reference_mul(&self.denominator, &other.denominator);
        }

        fn finalize(&self) -> [u8; BYTE_LEN] {
            let denominator = reference_reduce(&self.denominator);
            let quotient = match denominator.inv_mod(MODULUS) {
                Some(inverse) => reference_mul(&reference_reduce(&self.numerator), &inverse),
                None => U3072::ZERO,
            };
            quotient.to_be_bytes::<BYTE_LEN>()
        }

        fn finalize_hash(&self) -> Hash256 {
            let mut element = self.finalize();
            element.reverse();
            let digest: [u8; 32] = Sha256::digest(element).into();
            Hash256::from_le_bytes(&digest)
        }

        fn numerator_bytes(&self) -> [u8; BYTE_LEN] {
            reference_reduce(&self.numerator).to_be_bytes::<BYTE_LEN>()
        }

        fn denominator_bytes(&self) -> [u8; BYTE_LEN] {
            reference_reduce(&self.denominator).to_be_bytes::<BYTE_LEN>()
        }
    }

    fn reference_element(data: &[u8]) -> U3072 {
        let key: [u8; 32] = Sha256::digest(data).into();
        let mut stream = [0_u8; BYTE_LEN];
        chacha20_keystream(&key, &mut stream);
        reference_reduce(&U3072::from_le_bytes(stream))
    }

    fn reference_mul(left: &U3072, right: &U3072) -> U3072 {
        (*left).mul_mod(*right, MODULUS)
    }

    fn reference_reduce(value: &U3072) -> U3072 {
        (*value).reduce_mod(MODULUS)
    }

    fn num_from_ruint(value: &U3072) -> Num3072 {
        Num3072::from_le_bytes(&value.to_le_bytes::<BYTE_LEN>())
    }

    fn boundary_values() -> Vec<U3072> {
        let mut low_carry_limbs = [0_u64; LIMBS];
        low_carry_limbs[0] = u64::MAX;
        low_carry_limbs[1] = u64::MAX;
        low_carry_limbs[2] = 1;

        vec![
            U3072::ZERO,
            U3072::ONE,
            MODULUS - U3072::ONE,
            MODULUS,
            MODULUS + U3072::ONE,
            U3072::from_limbs(low_carry_limbs),
            U3072::MAX,
        ]
    }

    #[test]
    fn element_limbs_match_chacha20_byte_stream() {
        for data in [b"".as_slice(), b"alpha", b"coin stats muhash element"] {
            let key: [u8; 32] = Sha256::digest(data).into();
            let mut stream = [0_u8; BYTE_LEN];
            chacha20_keystream(&key, &mut stream);

            assert_eq!(element(data), Num3072::from_le_bytes(&stream));
        }
    }

    #[test]
    fn operation_sequence_matches_reference_oracle() {
        let mut candidate = MuHash3072::new();
        let mut reference = ReferenceMuHash3072::new();

        for data in [b"alpha".as_slice(), b"beta", b"gamma", b"alpha"] {
            candidate.insert(data);
            reference.insert(data);
        }
        candidate.remove(b"beta");
        reference.remove(b"beta");

        let mut candidate_other = MuHash3072::new();
        let mut reference_other = ReferenceMuHash3072::new();
        candidate_other.insert(b"delta");
        reference_other.insert(b"delta");
        candidate_other.remove(b"gamma");
        reference_other.remove(b"gamma");

        candidate.combine(&candidate_other);
        reference.combine(&reference_other);

        assert_eq!(candidate.finalize(), reference.finalize());
        assert_eq!(candidate.finalize_hash(), reference.finalize_hash());
        assert_eq!(candidate.numerator_bytes(), reference.numerator_bytes());
        assert_eq!(candidate.denominator_bytes(), reference.denominator_bytes());
    }

    #[test]
    fn from_parts_matches_reference_oracle() {
        let mut reference = ReferenceMuHash3072::new();
        reference.insert(b"persisted numerator");
        reference.remove(b"persisted denominator");
        reference.insert(b"second numerator");

        let numerator = reference.numerator_bytes();
        let denominator = reference.denominator_bytes();
        let candidate = MuHash3072::from_parts(&numerator, &denominator);

        assert_eq!(candidate.finalize(), reference.finalize());
        assert_eq!(candidate.finalize_hash(), reference.finalize_hash());
        assert_eq!(candidate.numerator_bytes(), numerator);
        assert_eq!(candidate.denominator_bytes(), denominator);
    }

    #[test]
    fn boundary_multiplication_matches_reference_oracle() {
        let values = boundary_values();

        for left in &values {
            for right in &values {
                let mut candidate = num_from_ruint(left);
                candidate.multiply(&num_from_ruint(right));

                assert_eq!(candidate.to_reduced_ruint(), left.mul_mod(*right, MODULUS));
            }
        }
    }

    #[test]
    fn from_parts_boundary_bytes_match_reference_oracle() {
        let values = boundary_values();

        for numerator_value in &values {
            for denominator_value in &values {
                let numerator = numerator_value.to_be_bytes::<BYTE_LEN>();
                let denominator = denominator_value.to_be_bytes::<BYTE_LEN>();
                let candidate = MuHash3072::from_parts(&numerator, &denominator);
                let reference = ReferenceMuHash3072::from_parts(&numerator, &denominator);

                assert_eq!(candidate.finalize(), reference.finalize());
                assert_eq!(candidate.finalize_hash(), reference.finalize_hash());
                assert_eq!(candidate.numerator_bytes(), reference.numerator_bytes());
                assert_eq!(candidate.denominator_bytes(), reference.denominator_bytes());
            }
        }
    }

    proptest! {
        #[test]
        fn generated_multiplication_matches_reference_oracle(
            left_limbs in proptest::collection::vec(any::<u64>(), LIMBS),
            right_limbs in proptest::collection::vec(any::<u64>(), LIMBS),
        ) {
            let mut left_array = [0_u64; LIMBS];
            let mut right_array = [0_u64; LIMBS];
            left_array.copy_from_slice(&left_limbs);
            right_array.copy_from_slice(&right_limbs);

            let left = U3072::from_limbs(left_array);
            let right = U3072::from_limbs(right_array);
            let mut candidate = Num3072 { limbs: left_array };
            candidate.multiply(&Num3072 { limbs: right_array });

            prop_assert_eq!(candidate.to_reduced_ruint(), left.mul_mod(right, MODULUS));
        }

        #[test]
        fn generated_operation_sequences_match_reference_oracle(
            ops in proptest::collection::vec(
                (
                    0_u8..3,
                    proptest::collection::vec(any::<u8>(), 0..80),
                    proptest::collection::vec(any::<u8>(), 0..80),
                ),
                0..128,
            )
        ) {
            let mut candidate = MuHash3072::new();
            let mut reference = ReferenceMuHash3072::new();

            for (op, first, second) in ops {
                match op {
                    0 => {
                        candidate.insert(&first);
                        reference.insert(&first);
                    }
                    1 => {
                        candidate.remove(&first);
                        reference.remove(&first);
                    }
                    _ => {
                        let mut candidate_other = MuHash3072::new();
                        let mut reference_other = ReferenceMuHash3072::new();
                        candidate_other.insert(&first);
                        reference_other.insert(&first);
                        candidate_other.remove(&second);
                        reference_other.remove(&second);
                        candidate.combine(&candidate_other);
                        reference.combine(&reference_other);
                    }
                }

                prop_assert_eq!(candidate.finalize(), reference.finalize());
                prop_assert_eq!(candidate.finalize_hash(), reference.finalize_hash());
                prop_assert_eq!(candidate.numerator_bytes(), reference.numerator_bytes());
                prop_assert_eq!(candidate.denominator_bytes(), reference.denominator_bytes());
            }
        }
    }
}
