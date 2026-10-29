#![allow(clippy::inline_always)]

use bitcoin_rs_primitives::Hash256;
use ruint::Uint;
use sha2::{Digest, Sha256};

const BYTE_LEN: usize = 384;
const LIMBS: usize = 48;
const LIMB_BITS: usize = 64;
const MAX_PRIME_DIFF: u64 = 1_103_717;

type U3072 = Uint<3072, LIMBS>;

const MODULUS: U3072 = {
    let mut limbs = [u64::MAX; LIMBS];
    limbs[0] -= MAX_PRIME_DIFF - 1;
    U3072::from_limbs(limbs)
};

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
        for (idx, chunk) in bytes.as_chunks::<8>().0.iter().enumerate() {
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
        for (chunk, limb) in out.as_chunks_mut::<8>().0.iter_mut().zip(self.limbs) {
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MuHash3072 {
    numerator: Num3072,
    denominator: Num3072,
}

impl MuHash3072 {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            numerator: Num3072::ONE,
            denominator: Num3072::ONE,
        }
    }

    pub fn insert(&mut self, data: &[u8]) {
        self.numerator.multiply(&element(data));
    }

    pub fn remove(&mut self, data: &[u8]) {
        self.denominator.multiply(&element(data));
    }

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
    for limb_block in limbs.as_chunks_mut::<8>().0 {
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
    for block in out.as_chunks_mut::<64>().0 {
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
    for (chunk, word) in out.as_chunks_mut::<4>().0.iter_mut().zip(words) {
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
mod tests;
