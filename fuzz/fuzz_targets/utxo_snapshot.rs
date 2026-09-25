#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;

/// Fuzz the complete version-4 snapshot contract used by checkpoint loading.
/// The observed entry point with the unit observer is the general form of
/// the strict decode and covers the whole strict-v4 contract: unsupported
/// versions, malformed records, missing trailers, and trailing bytes.
fuzz_target!(|data: &[u8]| {
    let mut cursor = Cursor::new(data);
    let _ = bitcoin_rs_utxo::read_snapshot_strict_v4_observed(&mut cursor, ());
});
