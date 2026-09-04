//! Eight-way SHA256d for fixed 64-byte Merkle parent inputs.
//!
//! The algorithm and lane contract follow Bitcoin Core v31.0
//! `src/crypto/sha256_avx2.cpp`. This module keeps runtime dispatch and the
//! target-feature boundary private. Callers hash independent Merkle pairs
//! through [`Avx2Sha256d64::transform_8way`] after [`detect_avx2`] succeeds;
//! otherwise they keep the scalar walker.

/// Number of independent 64-byte messages one [`Avx2Sha256d64`] transform hashes.
pub(crate) const LANES: usize = 8;

/// Proof that the current x86-64 process can execute AVX2 instructions.
pub(crate) struct Avx2Sha256d64(());

/// Detects AVX2 together with the operating-system extended-state support that
/// Rust's feature detector requires.
#[must_use]
pub(crate) fn detect_avx2() -> Option<Avx2Sha256d64> {
    #[cfg(target_arch = "x86_64")]
    {
        if std::is_x86_feature_detected!("avx2") {
            return Some(Avx2Sha256d64(()));
        }
    }
    None
}

impl Avx2Sha256d64 {
    /// Hashes eight independent 64-byte messages with SHA256(SHA256(message)).
    pub(crate) fn transform_8way(&self, input: &[[u8; 64]; 8], output: &mut [[u8; 32]; 8]) {
        let Self(()) = self;
        #[cfg(target_arch = "x86_64")]
        {
            // SAFETY: the token has no public constructor and `detect_avx2`
            // creates it only after Rust verifies CPU and OS AVX2 support.
            unsafe { x86_64::transform_8way(input, output) };
        }

        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = (input, output);
            unreachable!("an AVX2 token cannot be constructed on this architecture");
        }
    }
}

#[cfg(target_arch = "x86_64")]
mod x86_64 {
    use std::arch::x86_64::{
        __m256i, _mm256_add_epi32, _mm256_and_si256, _mm256_extract_epi32, _mm256_or_si256,
        _mm256_set1_epi32, _mm256_setr_epi32, _mm256_setzero_si256, _mm256_slli_epi32,
        _mm256_srli_epi32, _mm256_xor_si256,
    };

    const INITIAL_STATE: [u32; 8] = [
        0x6a09_e667,
        0xbb67_ae85,
        0x3c6e_f372,
        0xa54f_f53a,
        0x510e_527f,
        0x9b05_688c,
        0x1f83_d9ab,
        0x5be0_cd19,
    ];

    const ROUND_CONSTANTS: [u32; 64] = [
        0x428a_2f98,
        0x7137_4491,
        0xb5c0_fbcf,
        0xe9b5_dba5,
        0x3956_c25b,
        0x59f1_11f1,
        0x923f_82a4,
        0xab1c_5ed5,
        0xd807_aa98,
        0x1283_5b01,
        0x2431_85be,
        0x550c_7dc3,
        0x72be_5d74,
        0x80de_b1fe,
        0x9bdc_06a7,
        0xc19b_f174,
        0xe49b_69c1,
        0xefbe_4786,
        0x0fc1_9dc6,
        0x240c_a1cc,
        0x2de9_2c6f,
        0x4a74_84aa,
        0x5cb0_a9dc,
        0x76f9_88da,
        0x983e_5152,
        0xa831_c66d,
        0xb003_27c8,
        0xbf59_7fc7,
        0xc6e0_0bf3,
        0xd5a7_9147,
        0x06ca_6351,
        0x1429_2967,
        0x27b7_0a85,
        0x2e1b_2138,
        0x4d2c_6dfc,
        0x5338_0d13,
        0x650a_7354,
        0x766a_0abb,
        0x81c2_c92e,
        0x9272_2c85,
        0xa2bf_e8a1,
        0xa81a_664b,
        0xc24b_8b70,
        0xc76c_51a3,
        0xd192_e819,
        0xd699_0624,
        0xf40e_3585,
        0x106a_a070,
        0x19a4_c116,
        0x1e37_6c08,
        0x2748_774c,
        0x34b0_bcb5,
        0x391c_0cb3,
        0x4ed8_aa4a,
        0x5b9c_ca4f,
        0x682e_6ff3,
        0x748f_82ee,
        0x78a5_636f,
        0x84c8_7814,
        0x8cc7_0208,
        0x90be_fffa,
        0xa450_6ceb,
        0xbef9_a3f7,
        0xc671_78f2,
    ];

    #[target_feature(enable = "avx2")]
    pub(super) unsafe fn transform_8way(input: &[[u8; 64]; 8], output: &mut [[u8; 32]; 8]) {
        let zero = _mm256_setzero_si256();
        let mut first_block = [zero; 16];
        for (word, slot) in first_block.iter_mut().enumerate() {
            let offset = word * 4;
            *slot = _mm256_setr_epi32(
                read_word(&input[0], offset).cast_signed(),
                read_word(&input[1], offset).cast_signed(),
                read_word(&input[2], offset).cast_signed(),
                read_word(&input[3], offset).cast_signed(),
                read_word(&input[4], offset).cast_signed(),
                read_word(&input[5], offset).cast_signed(),
                read_word(&input[6], offset).cast_signed(),
                read_word(&input[7], offset).cast_signed(),
            );
        }

        // SAFETY: the capability token proves this target-feature boundary.
        let mut state = unsafe { initial_state() };
        // SAFETY: this function has AVX2 enabled and both arrays have the exact
        // fixed widths required by the compression function.
        unsafe { compress(&mut state, &first_block) };

        // A 64-byte message needs a second SHA-256 block containing 0x80,
        // zero padding, and the big-endian bit length 512 in word 15.
        let mut first_padding = [zero; 16];
        first_padding[0] = _mm256_set1_epi32(0x8000_0000_u32.cast_signed());
        first_padding[15] = _mm256_set1_epi32(512);
        // SAFETY: the same AVX2 and fixed-array contract applies.
        unsafe { compress(&mut state, &first_padding) };

        // The second SHA-256 hashes the 32-byte first digest. Its only block
        // contains eight digest words, 0x80 in word 8, and bit length 256.
        let mut second_block = [zero; 16];
        second_block[..8].copy_from_slice(&state);
        second_block[8] = _mm256_set1_epi32(0x8000_0000_u32.cast_signed());
        second_block[15] = _mm256_set1_epi32(256);
        // SAFETY: the same capability-token argument applies.
        state = unsafe { initial_state() };
        // SAFETY: the same AVX2 and fixed-array contract applies.
        unsafe { compress(&mut state, &second_block) };

        for (word, value) in state.into_iter().enumerate() {
            let lanes = [
                _mm256_extract_epi32::<0>(value),
                _mm256_extract_epi32::<1>(value),
                _mm256_extract_epi32::<2>(value),
                _mm256_extract_epi32::<3>(value),
                _mm256_extract_epi32::<4>(value),
                _mm256_extract_epi32::<5>(value),
                _mm256_extract_epi32::<6>(value),
                _mm256_extract_epi32::<7>(value),
            ];
            for (lane, lane_word) in lanes.into_iter().enumerate() {
                output[lane][word * 4..word * 4 + 4]
                    .copy_from_slice(&lane_word.cast_unsigned().to_be_bytes());
            }
        }
    }

    #[inline]
    fn read_word(message: &[u8; 64], offset: usize) -> u32 {
        u32::from_be_bytes([
            message[offset],
            message[offset + 1],
            message[offset + 2],
            message[offset + 3],
        ])
    }

    #[target_feature(enable = "avx2")]
    unsafe fn initial_state() -> [__m256i; 8] {
        INITIAL_STATE.map(|word| _mm256_set1_epi32(word.cast_signed()))
    }

    #[target_feature(enable = "avx2")]
    unsafe fn compress(state: &mut [__m256i; 8], block: &[__m256i; 16]) {
        // SAFETY: every helper below requires only AVX2, which this function's
        // target-feature contract provides. All array indices are bounded by
        // the fixed SHA-256 schedule and state sizes.
        unsafe {
            let zero = _mm256_setzero_si256();
            let mut schedule = [zero; 64];
            schedule[..16].copy_from_slice(block);
            for index in 16..64 {
                schedule[index] = add4(
                    small_sigma1(schedule[index - 2]),
                    schedule[index - 7],
                    small_sigma0(schedule[index - 15]),
                    schedule[index - 16],
                );
            }

            let [
                mut state_a,
                mut state_b,
                mut state_c,
                mut state_d,
                mut state_e,
                mut state_f,
                mut state_g,
                mut state_h,
            ] = *state;
            for index in 0..64 {
                let round_1 = add5(
                    state_h,
                    big_sigma1(state_e),
                    choose(state_e, state_f, state_g),
                    _mm256_set1_epi32(ROUND_CONSTANTS[index].cast_signed()),
                    schedule[index],
                );
                let round_2 = add2(big_sigma0(state_a), majority(state_a, state_b, state_c));
                state_h = state_g;
                state_g = state_f;
                state_f = state_e;
                state_e = add2(state_d, round_1);
                state_d = state_c;
                state_c = state_b;
                state_b = state_a;
                state_a = add2(round_1, round_2);
            }

            state[0] = add2(state[0], state_a);
            state[1] = add2(state[1], state_b);
            state[2] = add2(state[2], state_c);
            state[3] = add2(state[3], state_d);
            state[4] = add2(state[4], state_e);
            state[5] = add2(state[5], state_f);
            state[6] = add2(state[6], state_g);
            state[7] = add2(state[7], state_h);
        }
    }

    #[inline]
    #[target_feature(enable = "avx2")]
    unsafe fn add2(a: __m256i, b: __m256i) -> __m256i {
        _mm256_add_epi32(a, b)
    }

    #[inline]
    #[target_feature(enable = "avx2")]
    unsafe fn add4(a: __m256i, b: __m256i, c: __m256i, d: __m256i) -> __m256i {
        // SAFETY: this helper has the same AVX2 target feature as `add2`.
        unsafe { add2(add2(a, b), add2(c, d)) }
    }

    #[inline]
    #[target_feature(enable = "avx2")]
    unsafe fn add5(
        first: __m256i,
        second: __m256i,
        third: __m256i,
        fourth: __m256i,
        fifth: __m256i,
    ) -> __m256i {
        // SAFETY: this helper has the same AVX2 target feature as its callees.
        unsafe { add2(add4(first, second, third, fourth), fifth) }
    }

    #[inline]
    #[target_feature(enable = "avx2")]
    unsafe fn choose(x: __m256i, y: __m256i, z: __m256i) -> __m256i {
        _mm256_xor_si256(z, _mm256_and_si256(x, _mm256_xor_si256(y, z)))
    }

    #[inline]
    #[target_feature(enable = "avx2")]
    unsafe fn majority(x: __m256i, y: __m256i, z: __m256i) -> __m256i {
        _mm256_or_si256(
            _mm256_and_si256(x, y),
            _mm256_and_si256(z, _mm256_or_si256(x, y)),
        )
    }

    #[inline]
    #[target_feature(enable = "avx2")]
    unsafe fn big_sigma0(x: __m256i) -> __m256i {
        _mm256_xor_si256(
            _mm256_xor_si256(
                _mm256_or_si256(_mm256_srli_epi32::<2>(x), _mm256_slli_epi32::<30>(x)),
                _mm256_or_si256(_mm256_srli_epi32::<13>(x), _mm256_slli_epi32::<19>(x)),
            ),
            _mm256_or_si256(_mm256_srli_epi32::<22>(x), _mm256_slli_epi32::<10>(x)),
        )
    }

    #[inline]
    #[target_feature(enable = "avx2")]
    unsafe fn big_sigma1(x: __m256i) -> __m256i {
        _mm256_xor_si256(
            _mm256_xor_si256(
                _mm256_or_si256(_mm256_srli_epi32::<6>(x), _mm256_slli_epi32::<26>(x)),
                _mm256_or_si256(_mm256_srli_epi32::<11>(x), _mm256_slli_epi32::<21>(x)),
            ),
            _mm256_or_si256(_mm256_srli_epi32::<25>(x), _mm256_slli_epi32::<7>(x)),
        )
    }

    #[inline]
    #[target_feature(enable = "avx2")]
    unsafe fn small_sigma0(x: __m256i) -> __m256i {
        _mm256_xor_si256(
            _mm256_xor_si256(
                _mm256_or_si256(_mm256_srli_epi32::<7>(x), _mm256_slli_epi32::<25>(x)),
                _mm256_or_si256(_mm256_srli_epi32::<18>(x), _mm256_slli_epi32::<14>(x)),
            ),
            _mm256_srli_epi32::<3>(x),
        )
    }

    #[inline]
    #[target_feature(enable = "avx2")]
    unsafe fn small_sigma1(x: __m256i) -> __m256i {
        _mm256_xor_si256(
            _mm256_xor_si256(
                _mm256_or_si256(_mm256_srli_epi32::<17>(x), _mm256_slli_epi32::<15>(x)),
                _mm256_or_si256(_mm256_srli_epi32::<19>(x), _mm256_slli_epi32::<13>(x)),
            ),
            _mm256_srli_epi32::<10>(x),
        )
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::hashes::{Hash as _, sha256d};

    use super::detect_avx2;

    #[test]
    fn avx2_matches_independent_sha256d_vectors() {
        let Some(avx2) = detect_avx2() else {
            eprintln!(
                "test avx2_matches_independent_sha256d_vectors: AVX2 unavailable — skipping AVX2 vector test"
            );
            return;
        };
        eprintln!("test avx2_matches_independent_sha256d_vectors: running with AVX2 backend");
        let mut input = [[0_u8; 64]; 8];
        for (lane, message) in input.iter_mut().enumerate() {
            let lane = match u8::try_from(lane) {
                Ok(lane) => lane,
                Err(error) => panic!("eight lanes fit u8: {error}"),
            };
            for (offset, byte) in message.iter_mut().enumerate() {
                let offset = match u8::try_from(offset) {
                    Ok(offset) => offset,
                    Err(error) => panic!("64-byte offsets fit u8: {error}"),
                };
                *byte = lane
                    .wrapping_mul(37)
                    .wrapping_add(offset)
                    .rotate_left(u32::from(lane % 7));
            }
        }
        let mut output = [[0_u8; 32]; 8];
        avx2.transform_8way(&input, &mut output);
        for (message, digest) in input.iter().zip(output) {
            assert_eq!(digest, sha256d::Hash::hash(message).to_byte_array());
        }
    }

    #[test]
    fn avx2_matches_literal_zero_message_digest() {
        let Some(avx2) = detect_avx2() else {
            eprintln!(
                "test avx2_matches_literal_zero_message_digest: AVX2 unavailable — skipping AVX2 zero-message test"
            );
            return;
        };
        eprintln!("test avx2_matches_literal_zero_message_digest: running with AVX2 backend");
        let input = [[0_u8; 64]; 8];
        let mut output = [[0_u8; 32]; 8];
        avx2.transform_8way(&input, &mut output);

        // Independent Python hashlib SHA256(SHA256(64 zero bytes)) oracle.
        let expected = [
            226, 246, 28, 63, 113, 209, 222, 253, 63, 169, 153, 223, 163, 105, 83, 117, 92, 105, 6,
            137, 121, 153, 98, 180, 139, 235, 216, 54, 151, 78, 140, 249,
        ];
        assert!(output.into_iter().all(|digest| digest == expected));
    }
}
