use super::{compact_len, tagged_hash, tapleaf_hash};
use crate::primitives::varint;
use sha2::{Digest, Sha256};
use std::cell::UnsafeCell;

const MAX_SCRIPT_LEN: usize = 253;

const STUB_TAG_DIGEST: [u8; 32] = [0x9a; 32];

const RECORDER_CAP: usize = 2 * 32 + 1 + 3 + MAX_SCRIPT_LEN;

const MESSAGE_CAP: usize = 1 + 3 + MAX_SCRIPT_LEN;

struct Record {
    bytes: [u8; RECORDER_CAP],
    len: usize,
}

struct Recorder(UnsafeCell<Record>);

// SAFETY: Kani runs each harness on a single thread, so the static recorder
// is only ever accessed by one execution context.
unsafe impl Sync for Recorder {}

static RECORDER: Recorder = Recorder(UnsafeCell::new(Record {
    bytes: [0_u8; RECORDER_CAP],
    len: 0,
}));

fn stub_digest(_data: &[u8]) -> [u8; 32] {
    STUB_TAG_DIGEST
}

fn stub_tag_engine(_tag: &[u8]) -> Sha256 {
    let mut engine = Sha256::new();
    super::hash_feed(&mut engine, &STUB_TAG_DIGEST);
    super::hash_feed(&mut engine, &STUB_TAG_DIGEST);
    engine
}

fn stub_feed(_engine: &mut Sha256, data: &[u8]) {
    // SAFETY: single-threaded harness, see the Sync impl above.
    let previous = unsafe { (*RECORDER.0.get()).len };
    assert!(
        previous + data.len() <= RECORDER_CAP,
        "recorder overflow: tapleaf stream exceeds its bound"
    );
    // SAFETY: single-threaded harness, see the Sync impl above.
    unsafe {
        let record = &mut *RECORDER.0.get();
        record.bytes[previous..previous + data.len()].copy_from_slice(data);
        record.len = previous + data.len();
    }
}

fn stub_finish(_engine: Sha256) -> [u8; 32] {
    [0_u8; 32]
}

fn record_reset() {
    // SAFETY: single-threaded harness, see the Sync impl above.
    unsafe {
        (*RECORDER.0.get()).len = 0;
    }
}

fn record_byte(index: usize) -> u8 {
    // SAFETY: single-threaded harness, see the Sync impl above.
    unsafe { (*RECORDER.0.get()).bytes[index] }
}

fn record_len() -> usize {
    // SAFETY: single-threaded harness, see the Sync impl above.
    unsafe { (*RECORDER.0.get()).len }
}

fn spec_compact_size(value: u64) -> ([u8; 9], usize) {
    let payload = value.to_le_bytes();
    if value <= 0xfc {
        ([payload[0], 0, 0, 0, 0, 0, 0, 0, 0], 1)
    } else if value <= 0xffff {
        ([0xfd, payload[0], payload[1], 0, 0, 0, 0, 0, 0], 3)
    } else if value <= 0xffff_ffff {
        (
            [
                0xfe, payload[0], payload[1], payload[2], payload[3], 0, 0, 0, 0,
            ],
            5,
        )
    } else {
        (
            [
                0xff, payload[0], payload[1], payload[2], payload[3], payload[4], payload[5],
                payload[6], payload[7],
            ],
            9,
        )
    }
}

fn expected_stream_len(script: &[u8]) -> usize {
    let (_, compact_size_len) = spec_compact_size(compact_len(script.len()));
    2 * 32 + 1 + compact_size_len + script.len()
}

fn expected_stream_byte(index: usize, leaf_version: u8, script: &[u8]) -> u8 {
    if index < 32 {
        STUB_TAG_DIGEST[index]
    } else if index < 64 {
        STUB_TAG_DIGEST[index - 32]
    } else if index == 64 {
        leaf_version
    } else {
        let (compact_size, compact_size_len) = spec_compact_size(compact_len(script.len()));
        let message_start = 65 + compact_size_len;
        if index < message_start {
            compact_size[index - 65]
        } else if index < message_start + script.len() {
            script[index - message_start]
        } else {
            0
        }
    }
}
// SCR-03
#[kani::proof]
#[kani::unwind(270)]
#[kani::stub(super::hash_digest, stub_digest)]
#[kani::stub(super::hash_feed, stub_feed)]
#[kani::stub(super::hash_finish, stub_finish)]
#[kani::stub(super::tag_engine, stub_tag_engine)]
fn tapleaf_hash_input_stream_matches_concatenation_and_spec() {
    let leaf_version: u8 = kani::any();
    let script_len: usize = kani::any();
    kani::assume(script_len <= MAX_SCRIPT_LEN);

    let script_buf: [u8; MAX_SCRIPT_LEN] = kani::any();
    let script = &script_buf[..script_len];

    record_reset();
    let _streaming_digest = tapleaf_hash(leaf_version, script);

    let index: usize = kani::any();
    kani::assume(index < RECORDER_CAP);
    assert!(
        record_len() == expected_stream_len(script),
        "streaming feed has the wrong length"
    );
    assert!(
        record_byte(index) == expected_stream_byte(index, leaf_version, script),
        "streaming feed differs from the BIP341 tapleaf input bytes"
    );

    record_reset();
    let encoded_len = varint::encode(compact_len(script.len()));
    let mut msg = [0_u8; MESSAGE_CAP];
    msg[0] = leaf_version;
    let head = 1 + encoded_len.len();
    msg[1..head].copy_from_slice(encoded_len.as_slice());
    msg[head..head + script.len()].copy_from_slice(script);
    let msg_len = head + script.len();

    let _oracle_digest = tagged_hash(b"TapLeaf", &msg[..msg_len]);

    let oracle_index: usize = kani::any();
    kani::assume(oracle_index < RECORDER_CAP);
    assert!(
        record_len() == expected_stream_len(script),
        "concatenation feed has the wrong length"
    );
    assert!(
        record_byte(oracle_index) == expected_stream_byte(oracle_index, leaf_version, script),
        "concatenation feed differs from the BIP341 tapleaf input bytes"
    );
}
