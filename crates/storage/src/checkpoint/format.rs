//! Exact checkpoint generation names, network identity, and digest encoding.

use super::CheckpointError;
use bitcoin_rs_primitives::Network;

pub(crate) fn generation_name(generation: u64) -> String {
    format!("gen-{generation:020}")
}

pub(crate) fn valid_generation_name(name: &str) -> bool {
    name.len() == 24
        && name.starts_with("gen-")
        && name[4..].bytes().all(|byte| byte.is_ascii_digit())
}

pub(crate) fn valid_staging_name(name: &str) -> bool {
    name.strip_prefix(".gen-")
        .and_then(|value| value.strip_suffix(".tmp"))
        .is_some_and(|digits| {
            digits.len() == 20 && digits.bytes().all(|byte| byte.is_ascii_digit())
        })
}

pub(crate) fn valid_current_temp_name(name: &str) -> bool {
    name.strip_prefix(".CURRENT-")
        .and_then(|value| value.strip_suffix(".tmp"))
        .is_some_and(|digits| {
            digits.len() == 20 && digits.bytes().all(|byte| byte.is_ascii_digit())
        })
}

pub fn network_name(network: Network) -> &'static str {
    match network {
        Network::Mainnet => "mainnet",
        Network::Testnet3 => "testnet",
        Network::Testnet4 => "testnet4",
        Network::Signet => "signet",
        Network::Regtest => "regtest",
    }
}

pub fn decode_hex<const N: usize>(encoded: &str) -> Result<[u8; N], CheckpointError> {
    let invalid = || {
        CheckpointError::Invalid(format!(
            "expected {} lowercase hexadecimal characters",
            N.saturating_mul(2)
        ))
    };
    if !bitcoin_rs_primitives::hex::is_lowercase_hex(encoded) {
        return Err(invalid());
    }
    bitcoin_rs_primitives::hex::hex_decode_array(encoded).map_err(|_| invalid())
}
