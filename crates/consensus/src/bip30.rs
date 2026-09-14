use bitcoin_rs_primitives::Hash256;

use crate::ConsensusError;

/// Core's BIP34 recheck limit: above it BIP30 duplicate scans always run.
pub const BIP34_IMPLIES_BIP30_LIMIT: u32 = 1_983_702;

/// The two mainnet blocks that duplicated a still-live txid before BIP30, keyed
/// by height AND block hash.
///
/// Height alone is not the exception. Bitcoin Core pins both hashes, and so
/// must this: keyed by height only, any regtest or signet block mined at 91,842
/// would inherit mainnet's exemption, and so would an alternate mainnet block at
/// that height. Either one accepts a duplicate txid that Core rejects, which is
/// a chain split.
///
/// Stored consensus little-endian (display hex reversed byte-wise), following
/// the convention in `bitcoin_rs_primitives::network`. Display hashes:
/// `00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec` and
/// `00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721`.
const BIP30_DUPLICATE_TXID_EXCEPTIONS: [(u32, Hash256); 2] = [
    (
        91_842,
        Hash256::from_le_bytes(&[
            0xec, 0xca, 0xe0, 0x00, 0xe3, 0xc8, 0xe4, 0xe0, 0x93, 0x93, 0x63, 0x60, 0x43, 0x1f,
            0x3b, 0x76, 0x03, 0xc5, 0x63, 0xc1, 0xff, 0x61, 0x81, 0x39, 0x0a, 0x4d, 0x0a, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ]),
    ),
    (
        91_880,
        Hash256::from_le_bytes(&[
            0x21, 0xd7, 0x7c, 0xcb, 0x4c, 0x08, 0x38, 0x6a, 0x04, 0xac, 0x01, 0x96, 0xae, 0x10,
            0xf6, 0xa1, 0xd2, 0xc2, 0xa3, 0x77, 0x55, 0x8c, 0xa1, 0x90, 0xf1, 0x43, 0x07, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ]),
    ),
];

/// Checks BIP30 duplicate-txid rejection with the historical exception list.
pub fn check_bip30(
    height: u32,
    block_hash: Hash256,
    has_duplicate_txid: bool,
) -> Result<(), ConsensusError> {
    if !has_duplicate_txid || is_bip30_exception(height, block_hash) {
        return Ok(());
    }
    Err(ConsensusError::Bip {
        bip: "BIP30",
        reason: format!("duplicate txid at non-exception height {height}"),
    })
}

/// Returns true if this exact block is one of the two historical BIP30
/// exceptions.
#[must_use]
pub fn is_bip30_exception(height: u32, block_hash: Hash256) -> bool {
    BIP30_DUPLICATE_TXID_EXCEPTIONS
        .iter()
        .any(|(exception_height, exception_hash)| {
            *exception_height == height && *exception_hash == block_hash
        })
}

#[cfg(test)]
mod tests {
    use bitcoin_rs_primitives::Hash256;

    use super::{BIP30_DUPLICATE_TXID_EXCEPTIONS, check_bip30, is_bip30_exception};

    fn exception(height: u32) -> Hash256 {
        BIP30_DUPLICATE_TXID_EXCEPTIONS
            .iter()
            .find(|(exception_height, _)| *exception_height == height)
            .map_or_else(
                || panic!("no BIP30 exception at height {height}"),
                |(_, hash)| *hash,
            )
    }

    /// Any hash that is not one of the two pinned ones.
    fn other_hash() -> Hash256 {
        Hash256::from_le_bytes(&[0x11; 32])
    }

    #[test]
    fn documented_duplicate_txid_exception_blocks_pass() {
        assert_eq!(check_bip30(91_842, exception(91_842), true), Ok(()));
        assert_eq!(check_bip30(91_880, exception(91_880), true), Ok(()));
        assert!(is_bip30_exception(91_842, exception(91_842)));
        assert!(is_bip30_exception(91_880, exception(91_880)));
    }

    /// The exception is the block, not the height.
    ///
    /// Keyed by height alone, a regtest or signet chain reaching 91,842 would
    /// inherit mainnet's exemption, and so would any alternate mainnet block at
    /// that height. Both accept a duplicate txid that Bitcoin Core rejects.
    #[test]
    fn a_different_block_at_an_exception_height_is_not_exempt() {
        assert!(!is_bip30_exception(91_842, other_hash()));
        assert!(!is_bip30_exception(91_880, other_hash()));
        assert!(check_bip30(91_842, other_hash(), true).is_err());
        assert!(check_bip30(91_880, other_hash(), true).is_err());
    }

    /// The two exception hashes are not interchangeable between their heights.
    #[test]
    fn an_exception_hash_at_the_wrong_height_is_not_exempt() {
        assert!(!is_bip30_exception(91_880, exception(91_842)));
        assert!(!is_bip30_exception(91_842, exception(91_880)));
    }

    #[test]
    fn original_coinbase_duplicate_txid_heights_fail() {
        assert!(check_bip30(91_722, other_hash(), true).is_err());
        assert!(check_bip30(91_812, other_hash(), true).is_err());
        assert!(!is_bip30_exception(91_722, other_hash()));
        assert!(!is_bip30_exception(91_812, other_hash()));
    }

    #[test]
    fn other_duplicate_txids_fail() {
        assert!(check_bip30(91_723, other_hash(), true).is_err());
    }

    /// No duplicate means no BIP30 question, at any height or hash.
    #[test]
    fn a_block_without_a_duplicate_txid_always_passes() {
        assert_eq!(check_bip30(91_723, other_hash(), false), Ok(()));
        assert_eq!(check_bip30(91_842, exception(91_842), false), Ok(()));
    }
}
