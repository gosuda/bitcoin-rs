//! Known-good tests for Electrum scripthash status hashing.
use bitcoin::hashes::Hash as _;
use bitcoin_rs_index::{HistoryEntry, compute_status_hash};

#[test]
fn status_hash_matches_electrum_history_algorithm() -> Result<(), Box<dyn std::error::Error>> {
    let mut history = Vec::with_capacity(10);
    for byte in 0_u8..10 {
        history.push(HistoryEntry::confirmed(
            bitcoin::Txid::from_byte_array([byte; 32]),
            u32::from(byte) + 1,
        ));
    }

    let Some(status) = compute_status_hash(&history) else {
        return Err("non-empty history did not produce a status hash".into());
    };

    assert_eq!(
        status.to_string(),
        "ca3894ce4f39e6b85465b66de94f63a6bc39f1419b0a198d49b3865b442740b6"
    );
    Ok(())
}

#[test]
fn empty_history_has_no_status_hash() {
    assert_eq!(compute_status_hash(&[]), None);
}
