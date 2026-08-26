//! Shared raw Base64 decoder for RPC auth and wallet PSBT paths.

use alloc::vec::Vec;

/// Decodes standard Base64 with `=` padding.
///
/// Returns `None` when the input length, alphabet, or padding is invalid.
pub(crate) fn decode(input: &str) -> Option<Vec<u8>> {
    let bytes = input.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return None;
    }

    let mut output = Vec::with_capacity(bytes.len() / 4 * 3);
    let mut index = 0;
    while index < bytes.len() {
        let a = decode_byte(bytes[index])?;
        let b = decode_byte(bytes[index + 1])?;
        let c = if bytes[index + 2] == b'=' {
            64
        } else {
            decode_byte(bytes[index + 2])?
        };
        let d = if bytes[index + 3] == b'=' {
            64
        } else {
            decode_byte(bytes[index + 3])?
        };
        if c == 64 && d != 64 {
            return None;
        }
        output.push((a << 2) | (b >> 4));
        if c != 64 {
            output.push(((b & 0x0f) << 4) | (c >> 2));
        }
        if d != 64 {
            output.push(((c & 0x03) << 6) | d);
        }
        index += 4;
    }
    Some(output)
}

fn decode_byte(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}
