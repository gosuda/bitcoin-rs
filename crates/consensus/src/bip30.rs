use crate::ConsensusError;

const BIP30_DUPLICATE_TXID_EXCEPTIONS: [u32; 2] = [91_842, 91_880];

/// Checks BIP30 duplicate-txid rejection with the historical exception list.
pub fn check_bip30(height: u32, has_duplicate_txid: bool) -> Result<(), ConsensusError> {
    if !has_duplicate_txid || BIP30_DUPLICATE_TXID_EXCEPTIONS.contains(&height) {
        return Ok(());
    }
    Err(ConsensusError::Bip {
        bip: "BIP30",
        reason: format!("duplicate txid at non-exception height {height}"),
    })
}

/// Returns true if `height` is one of the historical BIP30 exceptions.
#[must_use]
pub fn is_bip30_exception(height: u32) -> bool {
    BIP30_DUPLICATE_TXID_EXCEPTIONS.contains(&height)
}

#[cfg(test)]
mod tests {
    use super::{check_bip30, is_bip30_exception};

    #[test]
    fn documented_duplicate_txid_exception_heights_pass() {
        assert_eq!(check_bip30(91_842, true), Ok(()));
        assert_eq!(check_bip30(91_880, true), Ok(()));
        assert!(is_bip30_exception(91_842));
        assert!(is_bip30_exception(91_880));
    }

    #[test]
    fn original_coinbase_duplicate_txid_heights_fail() {
        assert!(check_bip30(91_722, true).is_err());
        assert!(check_bip30(91_812, true).is_err());
        assert!(!is_bip30_exception(91_722));
        assert!(!is_bip30_exception(91_812));
    }

    #[test]
    fn other_duplicate_txids_fail() {
        assert!(check_bip30(91_723, true).is_err());
    }
}
