//! Fixed compatibility coverage for the supported v4 snapshot format.
//!
//! The fixture was written by an earlier build and is checked only in the load
//! direction; current writers are not required to preserve internal byte order.
// A golden-vector test that cannot read its own fixture has failed; panicking
// names the step that broke.
#![allow(clippy::expect_used)]

use std::io::Cursor;

use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_primitives::encode::hex_encode;
use bitcoin_rs_utxo::read_snapshot_strict_v4;

/// A fixed v4 snapshot captured from an earlier build.
const GOLDEN: &[u8] = include_bytes!("fixtures/utxo-v4-golden.dat");

/// Commitment of the fixed coins in Core VARINT vout-key order. Independently
/// decoded from the fixture: numeric vout order gave the old 020e5a59... hash,
/// but differs at the 16,511/16,512 width transition (see core_snapshot tests).
const GOLDEN_HASH_HEX: &str = "0e318186eb68834de0ee996ac39e1dbc3f91f4c39936427d2455bd8d882ca422";

const GOLDEN_OUTPUTS: usize = 433;
const GOLDEN_TIP_HEIGHT: u32 = 412_732;

fn txid(seed: u64) -> Hash256 {
    let mut bytes = [0_u8; 32];
    bytes[..8].copy_from_slice(&seed.to_le_bytes());
    bytes[8..16].copy_from_slice(&seed.rotate_left(23).to_le_bytes());
    bytes[16..24].copy_from_slice(&seed.wrapping_mul(0x94d0_49bb_1331_11eb).to_le_bytes());
    bytes[24..32].copy_from_slice(&seed.wrapping_add(0x0123_4567_89ab_cdef).to_le_bytes());
    Hash256::from_le_bytes(&bytes)
}

/// The load direction: v4 bytes must still decode to the same consensus values.
#[test]
fn a_v4_snapshot_preserves_coins_and_trailer_with_core_key_order_commitment() {
    let loaded = read_snapshot_strict_v4(&mut Cursor::new(GOLDEN)).expect("v4 snapshot loads");

    assert_eq!(loaded.height, GOLDEN_TIP_HEIGHT);
    assert_eq!(loaded.tip_hash, txid(4_242));
    assert_eq!(loaded.set.len(), GOLDEN_OUTPUTS, "output count drifted");
    assert_eq!(
        loaded.muhash_trailer, [0_u8; 384],
        "the MuHash trailer must survive the load byte for byte"
    );
    assert_eq!(
        hex_encode(
            &loaded
                .set
                .lock_stable_view()
                .hash_serialized_3()
                .expect("hash")
                .to_le_bytes()
        ),
        GOLDEN_HASH_HEX,
        "the fixed v4 coins must retain their Core key-order commitment"
    );
}
