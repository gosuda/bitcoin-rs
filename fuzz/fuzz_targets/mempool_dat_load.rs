#![no_main]

use std::time::{Duration, Instant};

use bitcoin_rs_mempool::snapshot::Snapshot;
use bitcoin_rs_primitives::Network;
use libfuzzer_sys::fuzz_target;

const MAX_FUZZ_SNAPSHOT_BYTES: u64 = 1024 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let network = match data[0] % 4 {
        0 => Network::Mainnet,
        1 => Network::Testnet3,
        2 => Network::Regtest,
        _ => Network::Signet,
    };
    let payload = &data[1..];

    let deadline = Instant::now() + Duration::from_millis(100);

    if let Ok(snapshot) = Snapshot::decode(payload, network, MAX_FUZZ_SNAPSHOT_BYTES, deadline) {
        let _ = snapshot.order();
        let encode_deadline = Instant::now() + Duration::from_millis(100);
        if let Ok(encoded) = snapshot.encode(network, MAX_FUZZ_SNAPSHOT_BYTES, encode_deadline) {
            let decode_deadline = Instant::now() + Duration::from_millis(100);
            let roundtripped =
                Snapshot::decode(&encoded, network, MAX_FUZZ_SNAPSHOT_BYTES, decode_deadline);
            match roundtripped {
                Ok(rt) => assert_eq!(rt, snapshot),
                Err(err) => panic!("re-encoded snapshot failed to decode: {err:?}"),
            }
        }
    }
});
