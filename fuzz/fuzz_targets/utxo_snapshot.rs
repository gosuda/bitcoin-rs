#![no_main]

use std::io::Cursor;

use bitcoin_rs_primitives::Network;
use bitcoin_rs_utxo::core_snapshot::{SnapshotLimits, read_and_verify, read_metadata};
use libfuzzer_sys::fuzz_target;

// An independent, unmodified Core dump, with provenance and generator beside it.
const CORE_FIXTURE: &[u8] = include_bytes!("../../crates/utxo/tests/fixtures/core-v2/core200.dat");
const CORE_HEADER_BYTES: usize = 51;

// Fuzz native checkpoint v4 and bounded Core portable v2 input separately.
// The observed entry point with the unit observer is the general form of
// the strict decode and covers the whole strict-v4 contract: unsupported
// versions, malformed records, missing trailers, and trailing bytes.
fuzz_target!(|data: &[u8]| {
    let mut cursor = Cursor::new(data);
    let _ = bitcoin_rs_utxo::read_snapshot_strict_v4_observed(&mut cursor, ());
    let _ = read_metadata(&mut Cursor::new(data));
    let limits = SnapshotLimits {
        max_file_bytes: 1024 * 1024,
        max_coins: 1000,
        max_script_bytes: 100_000,
        max_coins_per_txid: 1000,
    };
    let _ = read_and_verify(&mut Cursor::new(data), Network::Regtest, limits);

    // Existing foreign/native corpus inputs need not guess a 256-bit compiled
    // anchor. Preserve the genuine header and use bounded input triples as
    // (little-endian body offset, XOR byte) patches into its valid coin body.
    // Empty/no-op inputs retain the complete positive Core fixture.
    let mut mutated = CORE_FIXTURE.to_vec();
    for &[low, high, xor] in data.as_chunks::<3>().0.iter().take(256) {
        let offset =
            usize::from(u16::from_le_bytes([low, high])) % (mutated.len() - CORE_HEADER_BYTES);
        mutated[CORE_HEADER_BYTES + offset] ^= xor;
    }
    let _ = read_and_verify(&mut Cursor::new(mutated), Network::Regtest, limits);
});
