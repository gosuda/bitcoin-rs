//! Base64 codec for the RPC crate, with one owner for the alphabet.
//!
//! Auth header decoding and PSBT rendering previously carried two decoders
//! whose acceptance rules had drifted. Both surfaces now share these
//! functions; the decoder accepts exactly the standard alphabet with
//! canonical padding, so every string one surface rejects the other
//! rejects too.

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Decodes standard-alphabet Base64 with canonical padding.
///
/// Padding follows RFC 4648: at most one pad block at the end, written as
/// `=` at the third or fourth position of the final chunk and nowhere else.
/// The empty string is not a valid encoding.
///
/// PRE: `input` is the string a caller received on its boundary.
/// POST: `Ok(bytes)` with the decoded octets, or `Err(())` for an empty,
///   non-multiple-of-four, wrongly padded, or off-alphabet input.
/// INVARIANT: `Ok` output round-trips through [`encode`].
pub(crate) fn decode(input: &str) -> Result<Vec<u8>, ()> {
    let bytes = input.as_bytes();
    if bytes.is_empty() || !bytes.len().is_multiple_of(4) {
        return Err(());
    }

    let chunk_count = bytes.len() / 4;
    let mut out = Vec::with_capacity(chunk_count * 3);
    for (index, chunk) in bytes.as_chunks::<4>().0.iter().enumerate() {
        let last = index + 1 == chunk_count;
        let pad2 = chunk[2] == b'=';
        let pad3 = chunk[3] == b'=';
        if chunk[0] == b'=' || chunk[1] == b'=' || pad2 && !pad3 || pad3 && !last {
            return Err(());
        }

        let Some(a) = value(chunk[0]) else {
            return Err(());
        };
        let Some(b) = value(chunk[1]) else {
            return Err(());
        };
        let c = if pad2 {
            0
        } else {
            let Some(value) = value(chunk[2]) else {
                return Err(());
            };
            value
        };
        let d = if pad3 {
            0
        } else {
            let Some(value) = value(chunk[3]) else {
                return Err(());
            };
            value
        };

        out.push((a << 2) | (b >> 4));
        if !pad2 {
            out.push((b << 4) | (c >> 2));
        }
        if !pad3 {
            out.push((c << 6) | d);
        }
    }

    Ok(out)
}

const fn value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Encodes bytes as standard-alphabet Base64 with canonical padding.
///
/// PRE: none; any byte slice encodes.
/// POST: the encoded string, padded to a multiple of four characters with
///   `=` only where a final chunk carries fewer than three octets.
/// INVARIANT: for non-empty `bytes`, `decode(&encode(bytes)) == Ok(bytes)`;
///   the empty slice encodes to the empty string, which [`decode`] rejects.
pub(crate) fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);

        out.push(char::from(ALPHABET[usize::from(b0 >> 2)]));
        out.push(char::from(
            ALPHABET[usize::from(((b0 & 0b0000_0011) << 4) | (b1 >> 4))],
        ));
        if chunk.len() > 1 {
            out.push(char::from(
                ALPHABET[usize::from(((b1 & 0b0000_1111) << 2) | (b2 >> 6))],
            ));
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(char::from(ALPHABET[usize::from(b2 & 0b0011_1111)]));
        } else {
            out.push('=');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{decode, encode};

    #[test]
    fn round_trip_preserves_bytes() {
        for input in [
            &b"f"[..],
            b"fo",
            b"foo",
            b"foob",
            b"fooba",
            b"foobar",
            &[0_u8, 255, 7, 128, 1][..],
        ] {
            assert_eq!(decode(&encode(input)), Ok(input.to_vec()));
        }
    }

    #[test]
    fn rfc4648_vectors_decode() {
        assert_eq!(decode("Zm8="), Ok(b"fo".to_vec()));
        assert_eq!(decode("Zm9v"), Ok(b"foo".to_vec()));
        assert_eq!(decode("Zm9vYmE="), Ok(b"fooba".to_vec()));
    }

    #[test]
    fn rejects_empty_unpadded_and_misplaced_padding() {
        assert!(decode("").is_err());
        assert!(decode("Zg").is_err());
        assert!(decode("Z==g").is_err());
        assert!(decode("Zg==Zg==").is_err());
        assert_eq!(decode("Zg=="), Ok(b"f".to_vec()));
    }
}
