//! Exact checkpoint generation names, network identity, and digest encoding.

use super::CheckpointError;
use bitcoin_rs_primitives::Network;

pub(super) fn generation_name(generation: u64) -> String {
    format!("gen-{generation:020}")
}

pub(super) fn valid_generation_name(name: &str) -> bool {
    name.len() == 24
        && name.starts_with("gen-")
        && name[4..].bytes().all(|byte| byte.is_ascii_digit())
}

pub(super) fn valid_staging_name(name: &str) -> bool {
    name.strip_prefix(".gen-")
        .and_then(|value| value.strip_suffix(".tmp"))
        .is_some_and(|digits| {
            digits.len() == 20 && digits.bytes().all(|byte| byte.is_ascii_digit())
        })
}

pub(super) fn valid_current_temp_name(name: &str) -> bool {
    name.strip_prefix(".CURRENT-")
        .and_then(|value| value.strip_suffix(".tmp"))
        .is_some_and(|digits| {
            digits.len() == 20 && digits.bytes().all(|byte| byte.is_ascii_digit())
        })
}

/// Checkpoint-file network spelling. Core's `testnet` alias names
/// [`Network::Testnet3`]. Evidence identity uses [`Network::identity_name`].
pub(super) fn network_name(network: Network) -> &'static str {
    match network {
        Network::Mainnet => "mainnet",
        Network::Testnet3 => "testnet",
        Network::Testnet4 => "testnet4",
        Network::Signet => "signet",
        Network::Regtest => "regtest",
    }
}

pub(super) fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

pub(super) fn decode_hex<const N: usize>(encoded: &str) -> Result<[u8; N], CheckpointError> {
    if encoded.len() != N.saturating_mul(2)
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(CheckpointError::Invalid(format!(
            "expected {} lowercase hexadecimal characters",
            N.saturating_mul(2)
        )));
    }
    let mut decoded = [0_u8; N];
    for (index, pair) in encoded.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        decoded[index] = (decode_nibble(pair[0]) << 4) | decode_nibble(pair[1]);
    }
    Ok(decoded)
}

pub(super) fn decode_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => 0,
    }
}
