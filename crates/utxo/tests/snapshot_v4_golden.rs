//! Fixed compatibility coverage for the supported v4 snapshot format.
//!
//! The fixture was written by an earlier build and is checked only in the load
//! direction; current writers are not required to preserve internal byte order.
// A golden-vector test that cannot read its own fixture has failed; panicking
// names the step that broke.
#![allow(clippy::expect_used)]

#[path = "support/seeded_txid.rs"]
mod seeded_txid;

use std::io::Cursor;

use bitcoin_rs_primitives::hex_encode;
use bitcoin_rs_utxo::{hash_serialized_3, read_snapshot_strict_v4};

use seeded_txid::txid;

/// A fixed v4 snapshot captured from an earlier build.
const GOLDEN: &[u8] = include_bytes!("fixtures/utxo-v4-golden.dat");

/// `hash_serialized_3` of that set, as the v4 build computed it.
const GOLDEN_HASH_HEX: &str = "020e5a59271f9db60e11102c4262702747676e868e80e7837b6e6d5fb05213ff";

const GOLDEN_OUTPUTS: usize = 433;
const GOLDEN_TIP_HEIGHT: u32 = 412_732;

/// The load direction: v4 bytes must still decode to the same consensus values.
#[test]
fn a_v4_snapshot_loads_to_the_hash_and_trailer_it_was_written_with() {
    let loaded = read_snapshot_strict_v4(&mut Cursor::new(GOLDEN)).expect("v4 snapshot loads");

    assert_eq!(loaded.height, GOLDEN_TIP_HEIGHT);
    assert_eq!(loaded.tip_hash, txid(4_242));
    assert_eq!(loaded.set.len(), GOLDEN_OUTPUTS, "output count drifted");
    assert_eq!(
        loaded.muhash_trailer, [0_u8; 384],
        "the MuHash trailer must survive the load byte for byte"
    );
    assert_eq!(
        hex_encode(&hash_serialized_3(&loaded.set).expect("hash").to_le_bytes()),
        GOLDEN_HASH_HEX,
        "a v4 snapshot no longer hashes to what the v4 build computed"
    );
}
