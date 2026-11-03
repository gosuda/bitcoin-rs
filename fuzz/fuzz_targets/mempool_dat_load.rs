#![no_main]

use std::time::{Duration, Instant};

use bitcoin::hashes::{Hash as _, sha256};
use bitcoin_rs_mempool::snapshot::Snapshot;
use bitcoin_rs_primitives::Network;
use libfuzzer_sys::fuzz_target;

const MAX_FUZZ_SNAPSHOT_BYTES: u64 = 1024 * 1024;
const NON_GATING_DEADLINE: Duration = Duration::from_secs(3600);
const MAGIC: &[u8; 8] = b"BRSMPOOL";
const VERSION: u32 = 2;

fuzz_target!(|data: &[u8]| {
    let Some((&network_byte, payload)) = data.split_first() else {
        return;
    };

    let network = match network_byte % 4 {
        0 => Network::Mainnet,
        1 => Network::Testnet3,
        2 => Network::Regtest,
        _ => Network::Signet,
    };

    let mut framed = Vec::with_capacity(payload.len() + 84);
    framed.extend_from_slice(MAGIC);
    framed.extend_from_slice(&VERSION.to_le_bytes());
    framed.extend_from_slice(&network.genesis_block_hash().to_le_bytes());
    framed.extend_from_slice(payload);
    let checksum = sha256::Hash::hash(&framed);
    framed.extend_from_slice(checksum.as_byte_array());

    let deadline = Instant::now() + NON_GATING_DEADLINE;

    if let Ok(snapshot) = Snapshot::decode(&framed, network, MAX_FUZZ_SNAPSHOT_BYTES, deadline) {
        let _ = snapshot.order();
        let encode_deadline = Instant::now() + NON_GATING_DEADLINE;
        if let Ok(encoded) = snapshot.encode(network, MAX_FUZZ_SNAPSHOT_BYTES, encode_deadline) {
            let decode_deadline = Instant::now() + NON_GATING_DEADLINE;
            let roundtripped =
                Snapshot::decode(&encoded, network, MAX_FUZZ_SNAPSHOT_BYTES, decode_deadline);
            match roundtripped {
                Ok(rt) => assert_eq!(rt, snapshot),
                Err(err) => panic!("re-encoded snapshot failed to decode: {err:?}"),
            }
        }
    }
});
