//! Compact encodings for UTXO record fields.
//!
//! These shrink the in-memory record payload, which a mainnet attribution run
//! measured at 55.1 bytes per live output and 77.4% of process RSS
//! (`docs/benchmarks/utxo-memory.md`). They are an **internal storage** format:
//! nothing here is consensus-visible, and `hash_serialized_3` and the MuHash
//! trailer are computed over decoded consensus values, not over these bytes.
//!
//! Two encodings, chosen because both are pure per-output transforms with no
//! cross-output invariant to violate:
//!
//! * [`varint`] — 7 bits per byte with a continuation flag, so the `vout` and
//!   script length that cost 4 and 2 fixed bytes cost one byte each for the
//!   values almost every output actually has.
//! * [`compress_amount`] — Bitcoin Core's `CTxOutCompressor` amount transform,
//!   which exploits how many amounts are round numbers of satoshis.

use crate::UtxoError;

/// Largest number of bytes a `u64` varint can occupy.
pub(crate) const VARINT_MAX_LEN: usize = 10;

/// Writes `value` as a base-128 varint into `out` starting at `at`, returning
/// the offset just past it, or `None` when `out` is too short.
///
/// Low 7 bits first, high bit set on every byte except the last.
///
/// Exists so an encoder can lay several varints into one stack buffer and issue
/// a single copy into the record, rather than one bounds-checked push per
/// field. That difference measured 3.2x on a 16-output record.
#[inline]
pub(crate) fn write_varint_at(value: u64, out: &mut [u8], at: usize) -> Option<usize> {
    let mut remaining = value;
    let mut cursor = at;
    loop {
        let mut byte = u8::try_from(remaining & 0x7f).unwrap_or(0);
        remaining >>= 7;
        if remaining != 0 {
            byte |= 0x80;
        }
        *out.get_mut(cursor)? = byte;
        cursor += 1;
        if remaining == 0 {
            return Some(cursor);
        }
    }
}

/// Bytes [`write_varint`] will produce for `value`.
///
/// The record encoder allocates one exact-capacity buffer, so it must know the
/// payload size before writing a byte. Kept beside `write_varint` and pinned
/// against it for every width boundary — a disagreement here is a buffer that
/// is too small (a `CorruptRecord` on a valid output) or one carrying slack.
#[inline]
pub(crate) const fn varint_len(value: u64) -> usize {
    let mut remaining = value >> 7;
    let mut len = 1;
    while remaining != 0 {
        remaining >>= 7;
        len += 1;
    }
    len
}

/// Reads a base-128 varint at `offset`, returning the value and the next offset.
///
/// Rejects a varint that runs off the end, that exceeds [`VARINT_MAX_LEN`]
/// bytes, whose final byte would overflow `u64`, or that is **not minimal**. A
/// record is decoded on every output read, so a malformed one must be an error
/// rather than a silently truncated value.
///
/// Minimality is what keeps the encoding injective in both directions, and the
/// v4 layout it replaces got that for free from fixed-width fields: `[0x80,
/// 0x00]` also decodes to zero, so accepting it would let two distinct byte
/// strings describe one record. `UtxoRecord` compares and hashes by bytes, so
/// that is not a cosmetic property.
#[inline]
pub(crate) fn read_varint(bytes: &[u8], offset: usize) -> Result<(u64, usize), UtxoError> {
    // Single-byte fast path. Every field this codec stores — vout, packed
    // height, script length, and a compressed round amount — is one byte for
    // the overwhelming majority of real outputs, so the general loop below is
    // the exception, not the rule.
    let first = *bytes.get(offset).ok_or(UtxoError::CorruptRecord)?;
    if first & 0x80 == 0 {
        // `get` succeeded, so `offset < bytes.len() <= isize::MAX`.
        return Ok((u64::from(first), offset + 1));
    }

    let mut value: u64 = 0;
    let mut shift = 0_u32;
    let mut cursor = offset;
    for _ in 0..VARINT_MAX_LEN {
        let byte = *bytes.get(cursor).ok_or(UtxoError::CorruptRecord)?;
        cursor += 1;
        let payload = u64::from(byte & 0x7f);
        // The tenth byte of a `u64` varint carries only one significant bit.
        if shift >= 64 || (shift == 63 && payload > 1) {
            return Err(UtxoError::CorruptRecord);
        }
        value |= payload << shift;
        if byte & 0x80 == 0 {
            // A continuation that contributes nothing is a longer spelling of a
            // shorter varint.
            if shift > 0 && payload == 0 {
                return Err(UtxoError::CorruptRecord);
            }
            return Ok((value, cursor));
        }
        shift += 7;
    }
    Err(UtxoError::CorruptRecord)
}

/// Largest amount the compression is defined for: 21,000,000 BTC in satoshis.
///
/// A consensus bound, not an arbitrary one — no UTXO can hold more. The
/// transform multiplies by 90, so it overflows `u64` above roughly 2e17; this
/// ceiling sits two orders of magnitude below that, and making the domain
/// explicit is better than a debug-only panic on a value that should be
/// impossible.
pub(crate) const MAX_COMPRESSIBLE_AMOUNT: u64 = 21_000_000 * 100_000_000;

/// Bitcoin Core's `CTxOutCompressor` amount compression.
///
/// Most amounts are round: a whole number of satoshis with a run of trailing
/// zeros. The transform factors out up to nine powers of ten and encodes the
/// exponent, so 1 BTC (100,000,000 sat) becomes a two-byte varint instead of
/// eight fixed bytes. Amounts that are not round cost one extra bit and are
/// still no worse than a plain varint.
///
/// Ported for the same reason Core uses it, and paired with
/// [`decompress_amount`] under an exhaustive-boundary and property round trip:
/// an amount that does not survive the round trip is a silently wrong balance.
#[inline]
pub(crate) const fn compress_amount(amount: u64) -> Result<u64, UtxoError> {
    if amount > MAX_COMPRESSIBLE_AMOUNT {
        return Err(UtxoError::AmountOutOfRange { value: amount });
    }
    if amount == 0 {
        return Ok(0);
    }
    let mut n = amount;
    let mut exponent = 0_u64;
    while n.is_multiple_of(10) && exponent < 9 {
        n /= 10;
        exponent += 1;
    }
    if exponent < 9 {
        let last_digit = n % 10;
        n /= 10;
        Ok(1 + (n * 9 + last_digit - 1) * 10 + exponent)
    } else {
        Ok(1 + (n - 1) * 10 + 9)
    }
}

// Counts `decompress_amount` calls so tests can assert *how much work* a record
// read does, instead of timing it. A wall-clock assertion in a test suite is a
// flake generator; this is the same claim made deterministically. Compiled only
// under `cfg(test)`, so production pays nothing.
#[cfg(test)]
thread_local! {
    pub(crate) static DECOMPRESS_CALLS: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}

/// The powers of ten the transform can factor out, indexed by exponent.
///
/// Replaces a `while` loop of up to nine dependent multiplies. Decoding an
/// amount is on the record read path, and that loop was most of its fixed cost.
const POW10: [u64; 10] = [
    1,
    10,
    100,
    1_000,
    10_000,
    100_000,
    1_000_000,
    10_000_000,
    100_000_000,
    1_000_000_000,
];

/// Inverse of [`compress_amount`], or `None` when `compressed` is not something
/// [`compress_amount`] could have produced.
///
/// The rejection is not defensive tidiness. `read_varint` will hand this any
/// `u64` a corrupt or hostile record contains, and the transform multiplies by
/// up to 10^9: `decompress_amount(u64::MAX)` is 2.05e22, which **panics in a
/// debug build** and wraps silently in a release one. `validate_encoded`
/// decodes every output of every record loaded from a snapshot, so that path is
/// reachable from a file on disk.
///
/// Requiring the result back inside the compressible domain also completes the
/// canonicality rule: the compact form may encode only amounts the escape
/// refuses, and the escape refuses exactly the amounts the compact form
/// covers. Together they leave each amount exactly one spelling.
#[inline]
pub(crate) fn decompress_amount(compressed: u64) -> Option<u64> {
    #[cfg(test)]
    DECOMPRESS_CALLS.with(|calls| calls.set(calls.get() + 1));

    if compressed == 0 {
        return Some(0);
    }
    let x = compressed - 1;
    let exponent = x % 10;
    let mut n = x / 10;
    if exponent < 9 {
        let last_digit = n % 9;
        n /= 9;
        n = n.checked_mul(10)?.checked_add(last_digit + 1)?;
    } else {
        n = n.checked_add(1)?;
    }
    // `exponent` is `x % 10`, so the lookup is in range by construction.
    let scale = POW10.get(usize::try_from(exponent).ok()?)?;
    let value = n.checked_mul(*scale)?;
    (value <= MAX_COMPRESSIBLE_AMOUNT).then_some(value)
}

#[cfg(test)]
// A codec test that cannot decode its own output has failed; panicking names
// the offending value.
#[expect(clippy::expect_used, reason = "test assertions")]
mod tests {
    use super::{
        MAX_COMPRESSIBLE_AMOUNT, VARINT_MAX_LEN, compress_amount, decompress_amount, read_varint,
        varint_len, write_varint_at,
    };

    /// Test shim for the removed fixed-buffer writer: the encoder lays varints
    /// into a shared buffer at an offset, so `write_varint_at` is the only
    /// writer, and these tests want "encode one, from zero".
    fn write_varint(value: u64, out: &mut [u8; VARINT_MAX_LEN]) -> usize {
        write_varint_at(value, out, 0).expect("a u64 varint fits VARINT_MAX_LEN")
    }
    use proptest::prelude::*;

    fn varint_roundtrip(value: u64) -> usize {
        let mut buf = [0_u8; VARINT_MAX_LEN];
        let len = write_varint(value, &mut buf);
        let (decoded, next) = read_varint(&buf, 0).expect("varint decodes");
        assert_eq!(decoded, value, "varint round trip failed for {value}");
        assert_eq!(
            next, len,
            "varint consumed the wrong byte count for {value}"
        );
        assert_eq!(
            varint_len(value),
            len,
            "varint_len disagreed with write_varint for {value}"
        );
        len
    }

    #[test]
    fn varint_round_trips_at_every_width_boundary() {
        // One byte per 7 bits, so each boundary is where the width steps up.
        for shift in 0..64_u32 {
            let value = 1_u64 << shift;
            varint_roundtrip(value);
            varint_roundtrip(value - 1);
        }
        varint_roundtrip(0);
        varint_roundtrip(u64::MAX);
    }

    #[test]
    fn varint_costs_one_byte_for_the_values_outputs_actually_have() {
        // This is the entire point of the change: `vout` and script lengths are
        // small, and were costing 4 and 2 fixed bytes.
        for value in [0_u64, 1, 2, 41, 127] {
            assert_eq!(varint_roundtrip(value), 1);
        }
        assert_eq!(varint_roundtrip(128), 2);
    }

    #[test]
    fn varint_rejects_a_truncated_or_overlong_encoding() {
        // Continuation bit set with nothing after it.
        assert!(read_varint(&[0x80], 0).is_err());
        assert!(read_varint(&[], 0).is_err());
        // Eleven continuation bytes cannot be a `u64`.
        assert!(read_varint(&[0xff; 11], 0).is_err());
        // Ten bytes whose final byte carries more than the one remaining bit.
        assert!(
            read_varint(
                &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02],
                0
            )
            .is_err()
        );
    }

    /// Two byte strings decoding to one value would break the record layer's
    /// byte equality, which the fixed-width v4 fields gave for free.
    #[test]
    fn varint_rejects_a_non_minimal_encoding() {
        // Longer spellings of 0, 1 and 128.
        for bytes in [
            vec![0x80, 0x00],
            vec![0x81, 0x00],
            vec![0x80, 0x80, 0x00],
            vec![0x80, 0x81, 0x00],
        ] {
            assert!(
                read_varint(&bytes, 0).is_err(),
                "non-minimal varint {bytes:?} was accepted"
            );
        }
        // The minimal spellings of the same values still decode.
        assert_eq!(read_varint(&[0x00], 0).expect("zero decodes").0, 0);
        assert_eq!(read_varint(&[0x01], 0).expect("one decodes").0, 1);
        assert_eq!(
            read_varint(&[0x80, 0x01], 0).expect("128 decodes").0,
            128,
            "a trailing byte that does contribute must stay valid"
        );
    }

    #[test]
    fn compressed_amounts_round_trip_over_bitcoin_relevant_values() {
        const COIN: u64 = 100_000_000;
        let mut values = vec![
            0,
            1,
            MAX_COMPRESSIBLE_AMOUNT,
            21_000_000 * COIN,
            50 * COIN,
            // The subsidy halvings, which is what most coinbase outputs are.
            25 * COIN,
            1_250_000_000,
            625_000_000,
        ];
        // Every power of ten, and its neighbours, since the transform factors
        // out powers of ten.
        let mut power = 1_u64;
        while let Some(next) = power.checked_mul(10) {
            if power > MAX_COMPRESSIBLE_AMOUNT {
                break;
            }
            values.extend([power, power + 1, power.saturating_sub(1)]);
            power = next;
        }
        for value in values {
            let compressed = compress_amount(value).expect("within the money supply");
            assert_eq!(
                decompress_amount(compressed),
                Some(value),
                "amount round trip failed for {value}"
            );
        }
    }

    #[test]
    fn an_amount_above_the_money_supply_errors_rather_than_overflowing() {
        assert!(compress_amount(MAX_COMPRESSIBLE_AMOUNT).is_ok());
        assert!(compress_amount(MAX_COMPRESSIBLE_AMOUNT + 1).is_err());
        assert!(compress_amount(u64::MAX).is_err());
    }

    #[test]
    fn a_round_amount_compresses_to_fewer_varint_bytes_than_it_costs_raw() {
        // 1 BTC is the shape the transform exists for: eight raw bytes today.
        let mut buf = [0_u8; VARINT_MAX_LEN];
        let compressed = compress_amount(100_000_000).expect("1 BTC is in range");
        let len = write_varint(compressed, &mut buf);
        assert!(
            len <= 2,
            "1 BTC should compress to at most 2 bytes, got {len}"
        );
    }

    proptest! {
        #[test]
        fn varint_round_trips(value in any::<u64>()) {
            let mut buf = [0_u8; VARINT_MAX_LEN];
            let len = write_varint(value, &mut buf);
            let (decoded, next) = read_varint(&buf, 0).expect("decodes");
            prop_assert_eq!(decoded, value);
            prop_assert_eq!(next, len);
        }

        #[test]
        fn compressed_amounts_round_trip(value in 0..=MAX_COMPRESSIBLE_AMOUNT) {
            let compressed = compress_amount(value).expect("in range");
            prop_assert_eq!(decompress_amount(compressed), Some(value));
        }

        /// No `u64` may panic the decoder, and every value it accepts must be
        /// one the encoder could have produced.
        ///
        /// `read_varint` hands this whatever a corrupt or hostile record
        /// contains, and `validate_encoded` runs it over every output of every
        /// record loaded from a snapshot. The second half is the canonicality
        /// rule: if some compressed value outside the encoder's image were
        /// accepted, one amount would have two spellings.
        #[test]
        fn decompress_accepts_exactly_the_encoder_image(compressed in any::<u64>()) {
            if let Some(value) = decompress_amount(compressed) {
                prop_assert!(value <= MAX_COMPRESSIBLE_AMOUNT);
                prop_assert_eq!(compress_amount(value).ok(), Some(compressed));
            }
        }

        /// The compression must be injective over the range it will ever see,
        /// or two distinct amounts would decode to one.
        #[test]
        fn compression_is_injective(
            a in 0..=MAX_COMPRESSIBLE_AMOUNT,
            b in 0..=MAX_COMPRESSIBLE_AMOUNT,
        ) {
            prop_assume!(a != b);
            let (ca, cb) = (compress_amount(a).expect("in range"), compress_amount(b).expect("in range"));
            prop_assert_ne!(ca, cb);
        }
    }
}
