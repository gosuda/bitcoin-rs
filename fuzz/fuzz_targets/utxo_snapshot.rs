#![no_main]

use std::io::Cursor;

use bitcoin_rs_primitives::Network;
use bitcoin_rs_utxo::core_snapshot::{SnapshotLimits, read_and_verify, read_metadata};
use libfuzzer_sys::fuzz_target;

// Fuzz native checkpoint v4 and bounded Core portable v2 input separately.
// The observed entry point with the unit observer is the general form of
// the strict decode and covers the whole strict-v4 contract: unsupported
// versions, malformed records, missing trailers, and trailing bytes.
fuzz_target!(|data: &[u8]| {
    let mut cursor = Cursor::new(data);
    let _ = bitcoin_rs_utxo::read_snapshot_strict_v4_observed(&mut cursor, ());
    let _ = read_metadata(&mut Cursor::new(data));
    let _ = read_and_verify(
        &mut Cursor::new(data),
        Network::Regtest,
        SnapshotLimits {
            max_file_bytes: 1024 * 1024,
            max_coins: 1000,
            max_script_bytes: 100_000,
            max_coins_per_txid: 1000,
            max_txids_per_prefix: 8,
        },
    );
});
