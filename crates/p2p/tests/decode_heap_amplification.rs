//! Transient decode allocation stays inside the pre-charged decode reservation.
#![expect(clippy::expect_used, reason = "fixture construction must fail loudly")]

use std::alloc::{GlobalAlloc, Layout, System};
use std::io::Cursor;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use bitcoin::p2p::Magic;
use bitcoin_rs_p2p::wire::{Message, PeerError, read_message};
use sha2::{Digest, Sha256};

struct CountingAllocator;

static ALLOCATION_COUNTING: AtomicBool = AtomicBool::new(false);
static ALLOCATION_LIVE: AtomicUsize = AtomicUsize::new(0);
static ALLOCATION_PEAK: AtomicUsize = AtomicUsize::new(0);

fn grow(bytes: usize) {
    let live = ALLOCATION_LIVE.fetch_add(bytes, Ordering::SeqCst) + bytes;
    ALLOCATION_PEAK.fetch_max(live, Ordering::SeqCst);
}

// SAFETY: every call forwards to `System` with the caller's layout; the counters only observe sizes.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller upholds the `GlobalAlloc::alloc` contract for `layout`.
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() && ALLOCATION_COUNTING.load(Ordering::SeqCst) {
            grow(layout.size());
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller upholds the `GlobalAlloc::alloc_zeroed` contract for `layout`.
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() && ALLOCATION_COUNTING.load(Ordering::SeqCst) {
            grow(layout.size());
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        if ALLOCATION_COUNTING.load(Ordering::SeqCst) {
            ALLOCATION_LIVE.fetch_sub(layout.size(), Ordering::SeqCst);
        }
        // SAFETY: the caller passes a pointer and layout from a matching `alloc` call.
        unsafe { System.dealloc(pointer, layout) };
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: the caller upholds the `GlobalAlloc::realloc` contract.
        let moved = unsafe { System.realloc(pointer, layout, new_size) };
        if !moved.is_null() && ALLOCATION_COUNTING.load(Ordering::SeqCst) {
            ALLOCATION_LIVE.fetch_sub(layout.size(), Ordering::SeqCst);
            grow(new_size);
        }
        moved
    }
}

#[global_allocator]
static DECODE_HEAP_TESTS_ALLOCATOR: CountingAllocator = CountingAllocator;

fn checksum(payload: &[u8]) -> [u8; 4] {
    let first = Sha256::digest(payload);
    let second = Sha256::digest(first);
    [second[0], second[1], second[2], second[3]]
}

fn blocktxn_frame(payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&Magic::REGTEST.to_bytes());
    let mut command = [0u8; 12];
    command[..8].copy_from_slice(b"blocktxn");
    frame.extend_from_slice(&command);
    let len = u32::try_from(payload.len()).expect("payload fits u32");
    frame.extend_from_slice(&len.to_le_bytes());
    frame.extend_from_slice(&checksum(payload));
    frame.extend_from_slice(payload);
    frame
}

fn one_witness_input_blocktxn_payload() -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&[0x07; 32]);
    payload.push(0x01);
    payload.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01]);
    payload.extend_from_slice(&[0x00; 32]);
    payload.extend_from_slice(&[0xFF; 4]);
    payload.extend_from_slice(&[0x00]);
    payload.extend_from_slice(&[0xFF; 4]);
    payload.extend_from_slice(&[0x01]);
    payload.extend_from_slice(&[0x00; 8]);
    payload.extend_from_slice(&[0x00]);
    payload.extend_from_slice(&[0xFE, 0x00, 0x09, 0x3D, 0x00]);
    payload
}

#[test]
fn blocktxn_decode_allocation_stays_within_the_reservation() {
    let invalid_payload = one_witness_input_blocktxn_payload();
    let invalid_reservation = bitcoin_rs_primitives::layout::decode_reservation(invalid_payload.len());
    let invalid_frame = blocktxn_frame(&invalid_payload);

    ALLOCATION_LIVE.store(0, Ordering::SeqCst);
    ALLOCATION_PEAK.store(0, Ordering::SeqCst);
    ALLOCATION_COUNTING.store(true, Ordering::SeqCst);
    let invalid_outcome = read_message(&mut Cursor::new(invalid_frame), Magic::REGTEST);
    ALLOCATION_COUNTING.store(false, Ordering::SeqCst);
    let invalid_peak = ALLOCATION_PEAK.load(Ordering::SeqCst);
    assert!(
        invalid_peak <= invalid_reservation,
        "transient decode allocation {invalid_peak} exceeded the {invalid_reservation}-byte reservation for a {}-byte payload",
        invalid_payload.len()
    );
    assert!(
        matches!(invalid_outcome, Err(PeerError::NativeDecode(_))),
        "4,000,000 declared witness items cannot exist in the remaining bytes: {invalid_outcome:?}"
    );

    let mut payload = Vec::new();
    payload.extend_from_slice(&[0x07; 32]);
    let mut transaction = Vec::new();
    transaction.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01]);
    transaction.extend_from_slice(&[0x00; 32]);
    transaction.extend_from_slice(&[0xFF; 4]);
    transaction.extend_from_slice(&[0x00]);
    transaction.extend_from_slice(&[0xFF; 4]);
    transaction.extend_from_slice(&[0x01]);
    transaction.extend_from_slice(&[0x00; 8]);
    transaction.extend_from_slice(&[0x00]);
    transaction.extend_from_slice(&[0x01, 0x01, 0x2A]);
    transaction.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    payload.push(0x01);
    payload.extend_from_slice(&transaction);

    let reservation = bitcoin_rs_primitives::layout::decode_reservation(payload.len());
    let frame = blocktxn_frame(&payload);

    ALLOCATION_LIVE.store(0, Ordering::SeqCst);
    ALLOCATION_PEAK.store(0, Ordering::SeqCst);
    ALLOCATION_COUNTING.store(true, Ordering::SeqCst);
    let outcome = read_message(&mut Cursor::new(frame), Magic::REGTEST);
    ALLOCATION_COUNTING.store(false, Ordering::SeqCst);

    let (message, _) = outcome.expect("a valid blocktxn decodes");
    assert!(matches!(message, Message::BlockTxn(_)));
    let peak = ALLOCATION_PEAK.load(Ordering::SeqCst);
    assert!(
        peak <= reservation,
        "transient decode allocation {peak} exceeded the {reservation}-byte reservation for a {}-byte payload",
        payload.len()
    );
}
