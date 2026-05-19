//! Proof round-trip coverage for the public Utreexo bridge and Stump wrappers.

use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_utreexo::{Accumulator, Bridge};
use proptest::prelude::*;

fn fake_hash(index: usize) -> Hash256 {
    let mut bytes = [0_u8; 32];
    bytes[..8].copy_from_slice(&u64::try_from(index).unwrap_or_default().to_le_bytes());
    Hash256::from_le_bytes(&bytes)
}

proptest! {
    #[test]
    fn proof_generated_by_bridge_deletes_from_fresh_stump(positions in proptest::collection::btree_set(0_usize..100, 1..20)) {
        let leaves: Vec<Hash256> = (0..100).map(fake_hash).collect();
        let delete_indexes: Vec<usize> = positions.iter().copied().collect();
        let delete_hashes: Vec<Hash256> = positions.iter().map(|index| leaves[*index]).collect();

        let mut bridge = Bridge::new();
        bridge.ingest_hashes(&leaves)?;

        let mut stump = Accumulator::new_stump();
        stump.add(&leaves)?;

        let proof = bridge.generate_proof(&delete_hashes)?;
        stump.delete(&delete_indexes, &[proof])?;
        bridge.delete_hashes(&delete_hashes)?;

        prop_assert_eq!(stump.roots(), bridge.roots());
    }
}
