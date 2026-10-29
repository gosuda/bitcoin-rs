//! Compact encodings for UTXO record fields.

use core::cmp::Ordering;

use crate::UtxoError;
use bitcoin_rs_primitives::Amount;

pub(crate) const VARINT_MAX_LEN: usize = 10;

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

#[inline]
pub(crate) fn read_varint(bytes: &[u8], offset: usize) -> Result<(u64, usize), UtxoError> {
    let first = *bytes.get(offset).ok_or(UtxoError::CorruptRecord)?;
    if first & 0x80 == 0 {
        return Ok((u64::from(first), offset + 1));
    }

    let mut value: u64 = 0;
    let mut shift = 0_u32;
    let mut cursor = offset;
    for _ in 0..VARINT_MAX_LEN {
        let byte = *bytes.get(cursor).ok_or(UtxoError::CorruptRecord)?;
        cursor += 1;
        let payload = u64::from(byte & 0x7f);
        if shift >= 64 || (shift == 63 && payload > 1) {
            return Err(UtxoError::CorruptRecord);
        }
        value |= payload << shift;
        if byte & 0x80 == 0 {
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
pub(crate) const MAX_COMPRESSIBLE_AMOUNT: u64 = Amount::MAX_MONEY.to_sat();

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

#[inline]
pub(crate) fn decompress_amount(compressed: u64) -> Option<u64> {
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
    let scale = POW10.get(usize::try_from(exponent).ok()?)?;
    let value = n.checked_mul(*scale)?;
    (value <= MAX_COMPRESSIBLE_AMOUNT).then_some(value)
}

/// Writes `value` as Bitcoin Core's subtract-one MSB VARINT into `out`.
pub(crate) fn write_core_varint(mut value: u64, out: &mut Vec<u8>) {
    let mut buf = [0_u8; 10];
    let mut len = 0;
    loop {
        buf[len] = u8::try_from(value & 0x7f).unwrap_or(0) | if len == 0 { 0 } else { 0x80 };
        len += 1;
        if value <= 0x7f {
            break;
        }
        value = (value >> 7) - 1;
    }
    for i in (0..len).rev() {
        out.push(buf[i]);
    }
}

#[inline]
pub(crate) fn encode_core_varint_array(mut value: u64) -> ([u8; 10], usize) {
    let mut reversed = [0_u8; 10];
    let mut len = 0;
    loop {
        reversed[len] = u8::try_from(value & 0x7f).unwrap_or(0) | if len == 0 { 0 } else { 0x80 };
        len += 1;
        if value <= 0x7f {
            break;
        }
        value = (value >> 7) - 1;
    }
    let mut out = [0_u8; 10];
    for i in 0..len {
        out[i] = reversed[len - 1 - i];
    }
    (out, len)
}

/// Compares two vouts by Core's coins-DB key order: bytewise order of the
/// subtract-one MSB VARINT encodings, which is the `LevelDB` cursor order that
/// defines Core's `HASH_SERIALIZED` commitment and dumptxoutset group order.
#[inline]
pub(crate) fn cmp_core_varint_key(left: u32, right: u32) -> Ordering {
    let (left_bytes, left_len) = encode_core_varint_array(u64::from(left));
    let (right_bytes, right_len) = encode_core_varint_array(u64::from(right));
    left_bytes[..left_len].cmp(&right_bytes[..right_len])
}

/// Compresses a scriptPubKey into Bitcoin Core's snapshot format.
///
/// Returns `None` for any other script, or for uncompressed P2PK with an invalid curve
/// point, prompting the caller to emit raw script length + 6.
pub(crate) fn compress_script(script: &[u8]) -> Option<(u64, &[u8])> {
    if script.len() == 25
        && script[0] == 0x76
        && script[1] == 0xa9
        && script[2] == 0x14
        && script[23] == 0x88
        && script[24] == 0xac
    {
        return Some((0, &script[3..23]));
    }
    if script.len() == 23 && script[0] == 0xa9 && script[1] == 0x14 && script[22] == 0x87 {
        return Some((1, &script[2..22]));
    }
    if script.len() == 35
        && script[0] == 0x21
        && (script[1] == 0x02 || script[1] == 0x03)
        && script[34] == 0xac
    {
        return Some((u64::from(script[1]), &script[2..34]));
    }
    if script.len() == 67
        && script[0] == 0x41
        && script[1] == 0x04
        && script[66] == 0xac
        && secp256k1::PublicKey::from_slice(&script[1..66]).is_ok()
    {
        let code = 4 + u64::from(script[65] & 1);
        return Some((code, &script[2..34]));
    }
    None
}

#[cfg(test)]
#[expect(clippy::expect_used, reason = "test assertions")]
mod tests {
    use super::{
        MAX_COMPRESSIBLE_AMOUNT, VARINT_MAX_LEN, compress_amount, decompress_amount, read_varint,
        varint_len, write_varint_at,
    };

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
    fn write_core_varint_encodes_reference_boundaries() {
        for (expected, value) in [
            (vec![0], 0),
            (vec![0x7f], 127),
            (vec![0x80, 0], 128),
            (vec![0xff, 0x7f], 16_511),
            (vec![0x80, 0x80, 0], 16_512),
        ] {
            let mut out = Vec::new();
            super::write_core_varint(value, &mut out);
            assert_eq!(out, expected);
        }
    }

    #[test]
    fn compress_script_handles_all_codes_and_fallbacks() {
        let pkh = [0x11; 20];
        let mut p2pkh = vec![0x76, 0xa9, 0x14];
        p2pkh.extend_from_slice(&pkh);
        p2pkh.extend_from_slice(&[0x88, 0xac]);
        assert_eq!(super::compress_script(&p2pkh), Some((0, &pkh[..])));

        let mut p2sh = vec![0xa9, 0x14];
        p2sh.extend_from_slice(&pkh);
        p2sh.push(0x87);
        assert_eq!(super::compress_script(&p2sh), Some((1, &pkh[..])));

        let mut comp2 = vec![0x21, 0x02];
        comp2.extend_from_slice(&[0xff; 32]);
        comp2.push(0xac);
        assert_eq!(super::compress_script(&comp2), Some((2, &[0xff; 32][..])));

        let mut comp3 = vec![0x21, 0x03];
        comp3.extend_from_slice(&[0xfe; 32]);
        comp3.push(0xac);
        assert_eq!(super::compress_script(&comp3), Some((3, &[0xfe; 32][..])));

        let gx = [
            0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
            0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b,
            0x16, 0xf8, 0x17, 0x98,
        ];
        let gy = [
            0x48, 0x3a, 0xda, 0x77, 0x26, 0xa3, 0xc4, 0x65, 0x5d, 0xa4, 0xfb, 0xfc, 0x0e, 0x11,
            0x08, 0xa8, 0xfd, 0x17, 0xb4, 0x48, 0xa6, 0x85, 0x54, 0x19, 0x9c, 0x47, 0xd0, 0x8f,
            0xfb, 0x10, 0xd4, 0xb8,
        ];
        let mut p2pk_g = vec![0x41, 0x04];
        p2pk_g.extend_from_slice(&gx);
        p2pk_g.extend_from_slice(&gy);
        p2pk_g.push(0xac);
        assert_eq!(super::compress_script(&p2pk_g), Some((4, &gx[..])));

        let neg_gy = [
            0xb7, 0xc5, 0x25, 0x88, 0xd9, 0x5c, 0x3b, 0x9a, 0xa2, 0x5b, 0x04, 0x03, 0xf1, 0xee,
            0xf7, 0x57, 0x02, 0xe8, 0x4b, 0xb7, 0x59, 0x7a, 0xab, 0xe6, 0x63, 0xb8, 0x2f, 0x6f,
            0x04, 0xef, 0x27, 0x77,
        ];
        let mut p2pk_neg_g = vec![0x41, 0x04];
        p2pk_neg_g.extend_from_slice(&gx);
        p2pk_neg_g.extend_from_slice(&neg_gy);
        p2pk_neg_g.push(0xac);
        assert_eq!(super::compress_script(&p2pk_neg_g), Some((5, &gx[..])));

        let mut invalid_uncompressed = p2pk_g.clone();
        invalid_uncompressed[2..34].fill(0xff);
        assert_eq!(super::compress_script(&invalid_uncompressed), None);

        assert_eq!(super::compress_script(&[0x51]), None);
        assert_eq!(super::compress_script(&[]), None);
    }

    #[test]
    fn varint_round_trips_at_every_width_boundary() {
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
        for value in [0_u64, 1, 2, 41, 127] {
            assert_eq!(varint_roundtrip(value), 1);
        }
        assert_eq!(varint_roundtrip(128), 2);
    }

    #[test]
    fn varint_rejects_a_truncated_or_overlong_encoding() {
        assert!(read_varint(&[0x80], 0).is_err());
        assert!(read_varint(&[], 0).is_err());
        assert!(read_varint(&[0xff; 11], 0).is_err());
        assert!(
            read_varint(
                &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02],
                0
            )
            .is_err()
        );
    }

    #[test]
    fn varint_rejects_a_non_minimal_encoding() {
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
            25 * COIN,
            1_250_000_000,
            625_000_000,
        ];
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

        #[test]
        fn decompress_accepts_exactly_the_encoder_image(compressed in any::<u64>()) {
            if let Some(value) = decompress_amount(compressed) {
                prop_assert!(value <= MAX_COMPRESSIBLE_AMOUNT);
                prop_assert_eq!(compress_amount(value).ok(), Some(compressed));
            }
        }

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
