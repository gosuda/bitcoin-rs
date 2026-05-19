use ruint::Uint;
use sha2::{Digest, Sha256};

const BYTE_LEN: usize = 384;
const LIMBS: usize = 48;
const PRIME_DIFF: u64 = 1_103_717;
const PRIME_SUB_FROM_MAX: u64 = PRIME_DIFF - 1;

type U3072 = Uint<3072, LIMBS>;

/// Running 3072-bit `MuHash` accumulator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MuHash3072 {
    numerator: U3072,
    denominator: U3072,
}

impl MuHash3072 {
    /// Creates the identity accumulator.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            numerator: U3072::ONE,
            denominator: U3072::ONE,
        }
    }

    /// Inserts one byte string into the multiset.
    pub fn insert(&mut self, data: &[u8]) {
        self.numerator = mul(&self.numerator, &element(data));
    }

    /// Removes one byte string from the multiset.
    pub fn remove(&mut self, data: &[u8]) {
        self.denominator = mul(&self.denominator, &element(data));
    }

    /// Combines another accumulator into this accumulator.
    pub fn combine(&mut self, other: &Self) {
        self.numerator = mul(&self.numerator, &other.numerator);
        self.denominator = mul(&self.denominator, &other.denominator);
    }

    /// Finalizes to the 3072-bit group element, serialized big-endian.
    #[must_use]
    pub fn finalize(&self) -> [u8; BYTE_LEN] {
        let prime = modulus();
        let denominator = reduce(&self.denominator);
        let quotient = match denominator.inv_mod(prime) {
            Some(inverse) => mul(&reduce(&self.numerator), &inverse),
            None => U3072::ZERO,
        };
        quotient.to_be_bytes::<BYTE_LEN>()
    }

    pub(crate) fn from_parts(numerator: &[u8; BYTE_LEN], denominator: &[u8; BYTE_LEN]) -> Self {
        Self {
            numerator: reduce(&U3072::from_be_bytes(*numerator)),
            denominator: reduce(&U3072::from_be_bytes(*denominator)),
        }
    }

    pub(crate) fn numerator_bytes(&self) -> [u8; BYTE_LEN] {
        reduce(&self.numerator).to_be_bytes::<BYTE_LEN>()
    }

    pub(crate) fn denominator_bytes(&self) -> [u8; BYTE_LEN] {
        reduce(&self.denominator).to_be_bytes::<BYTE_LEN>()
    }
}

impl Default for MuHash3072 {
    fn default() -> Self {
        Self::new()
    }
}

fn element(data: &[u8]) -> U3072 {
    let key: [u8; 32] = Sha256::digest(data).into();
    let mut stream = [0_u8; BYTE_LEN];
    chacha20_keystream(&key, &mut stream);
    reduce(&U3072::from_le_bytes(stream))
}

fn mul(left: &U3072, right: &U3072) -> U3072 {
    (*left).mul_mod(*right, modulus())
}

fn reduce(value: &U3072) -> U3072 {
    (*value).reduce_mod(modulus())
}

fn modulus() -> U3072 {
    U3072::MAX - U3072::from(PRIME_SUB_FROM_MAX)
}

fn chacha20_keystream(key: &[u8; 32], out: &mut [u8; BYTE_LEN]) {
    let mut block_counter = 0_u32;
    for block in out.chunks_exact_mut(64) {
        chacha20_block(key, block_counter, block);
        block_counter = block_counter.wrapping_add(1);
    }
}

fn chacha20_block(key: &[u8; 32], counter: u32, out: &mut [u8]) {
    let key_words = core::array::from_fn::<_, 8, _>(|idx| {
        let offset = idx * 4;
        u32::from_le_bytes([
            key[offset],
            key[offset + 1],
            key[offset + 2],
            key[offset + 3],
        ])
    });
    let state = [
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
        counter,
        0,
        0,
        0,
    ];
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

    for (chunk, word) in out.chunks_exact_mut(4).zip(working.into_iter().zip(state)) {
        chunk.copy_from_slice(&word.0.wrapping_add(word.1).to_le_bytes());
    }
}

fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(12);
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(7);
}
