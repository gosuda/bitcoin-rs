use super::*;
use proptest::prelude::*;

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
