//! Transient decode allocation stays inside the pre-charged decode reservation.
#![expect(clippy::expect_used, reason = "fixture construction must fail loudly")]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::io::Cursor;

use bitcoin::p2p::Magic;
use bitcoin_rs_wire::wire::{Message, PeerError, read_message};
use sha2::{Digest, Sha256};

thread_local! {
    static MEASURING: Cell<bool> = const { Cell::new(false) };
    static THREAD_ALLOCATION_LIVE: Cell<usize> = const { Cell::new(0) };
    static THREAD_ALLOCATION_PEAK: Cell<usize> = const { Cell::new(0) };
}

struct CountingAllocator;

fn measuring() -> bool {
    MEASURING.try_with(Cell::get).unwrap_or(false)
}

fn observe(live: usize) {
    THREAD_ALLOCATION_PEAK.with(|peak| {
        if live > peak.get() {
            peak.set(live);
        }
    });
}

fn grow(bytes: usize) {
    THREAD_ALLOCATION_LIVE.with(|live| {
        let next = live.get() + bytes;
        live.set(next);
        observe(next);
    });
}

// SAFETY: every call forwards to `System` with the caller's layout; the counters only observe sizes.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller upholds the `GlobalAlloc::alloc` contract for `layout`.
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() && measuring() {
            grow(layout.size());
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller upholds the `GlobalAlloc::alloc_zeroed` contract for `layout`.
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() && measuring() {
            grow(layout.size());
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        if measuring() {
            THREAD_ALLOCATION_LIVE.with(|live| live.set(live.get().saturating_sub(layout.size())));
        }
        // SAFETY: the caller passes a pointer and layout from a matching `alloc` call.
        unsafe { System.dealloc(pointer, layout) };
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: the caller upholds the `GlobalAlloc::realloc` contract.
        let moved = unsafe { System.realloc(pointer, layout, new_size) };
        if !moved.is_null() && measuring() {
            THREAD_ALLOCATION_LIVE.with(|live| {
                let next = live.get().saturating_sub(layout.size()) + new_size;
                live.set(next);
                observe(next);
            });
        }
        moved
    }
}

#[global_allocator]
static DECODE_HEAP_TESTS_ALLOCATOR: CountingAllocator = CountingAllocator;

struct Measurement;

impl Measurement {
    fn start() -> Self {
        MEASURING.with(|flag| flag.set(true));
        THREAD_ALLOCATION_LIVE.with(|live| live.set(0));
        THREAD_ALLOCATION_PEAK.with(|peak| peak.set(0));
        Measurement
    }

    fn peak(&self) -> usize {
        THREAD_ALLOCATION_PEAK.with(Cell::get)
    }
}

impl Drop for Measurement {
    fn drop(&mut self) {
        MEASURING.with(|flag| flag.set(false));
    }
}

fn checksum(payload: &[u8]) -> [u8; 4] {
    let first = Sha256::digest(payload);
    let second = Sha256::digest(first);
    [second[0], second[1], second[2], second[3]]
}

fn frame(command: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&Magic::REGTEST.to_bytes());
    let mut command_bytes = [0u8; 12];
    command_bytes[..command.len()].copy_from_slice(command);
    frame.extend_from_slice(&command_bytes);
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
    let invalid_reservation =
        bitcoin_rs_consensus::primitives::layout::decode_reservation(invalid_payload.len());
    let invalid_frame = frame(b"blocktxn", &invalid_payload);

    let measurement = Measurement::start();
    let invalid_outcome = read_message(&mut Cursor::new(invalid_frame), Magic::REGTEST);
    let invalid_peak = measurement.peak();
    drop(measurement);
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

    let reservation = bitcoin_rs_consensus::primitives::layout::decode_reservation(payload.len());
    let frame = frame(b"blocktxn", &payload);

    let measurement = Measurement::start();
    let outcome = read_message(&mut Cursor::new(frame), Magic::REGTEST);
    let peak = measurement.peak();
    drop(measurement);

    let (message, _) = outcome.expect("a valid blocktxn decodes");
    assert!(matches!(message, Message::BlockTxn(_)));
    assert!(
        peak <= reservation,
        "transient decode allocation {peak} exceeded the {reservation}-byte reservation for a {}-byte payload",
        payload.len()
    );
}

#[test]
fn cmpctblock_prefilled_transaction_decode_allocation_stays_within_the_reservation() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&[0x00; 80]);
    payload.extend_from_slice(&[0x00; 8]);
    payload.extend_from_slice(&[0x00, 0x01, 0x00]);
    payload.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01]);
    payload.extend_from_slice(&[0x00; 32]);
    payload.extend_from_slice(&[0xFF; 4]);
    payload.extend_from_slice(&[0x00]);
    payload.extend_from_slice(&[0xFF; 4]);
    payload.extend_from_slice(&[0x01]);
    payload.extend_from_slice(&[0x00; 8]);
    payload.extend_from_slice(&[0x00]);
    payload.extend_from_slice(&[0xFE, 0x00, 0x09, 0x3D, 0x00]);

    let reservation = bitcoin_rs_consensus::primitives::layout::decode_reservation(payload.len());
    let frame = frame(b"cmpctblock", &payload);

    let measurement = Measurement::start();
    let outcome = read_message(&mut Cursor::new(frame), Magic::REGTEST);
    let peak = measurement.peak();
    drop(measurement);
    assert!(
        peak <= reservation,
        "transient decode allocation {peak} exceeded the {reservation}-byte reservation for a {}-byte cmpctblock payload",
        payload.len()
    );
    assert!(
        matches!(outcome, Err(PeerError::NativeDecode(_))),
        "4,000,000 declared witness items cannot exist in the remaining bytes: {outcome:?}"
    );
}
