use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use bitcoin::absolute::LockTime;
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::consensus::serialize;
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, Block, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
use bitcoin_rs_primitives::BlockPayload;
use bitcoin_rs_primitives::layout::decode_reservation;
use bytes::Bytes;

struct CountingAllocator;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

fn grow(bytes: usize) {
    let live = LIVE.fetch_add(bytes, Ordering::SeqCst) + bytes;
    PEAK.fetch_max(live, Ordering::SeqCst);
}

// SAFETY: every call forwards to `System` with the caller's layout; the counters only observe sizes.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller upholds the `GlobalAlloc::alloc` contract for `layout`.
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            grow(layout.size());
        }
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller upholds the `GlobalAlloc::alloc_zeroed` contract for `layout`.
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() {
            grow(layout.size());
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::SeqCst);
        // SAFETY: the caller passes a pointer and layout from a matching `alloc` call.
        unsafe { System.dealloc(ptr, layout) };
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: the caller upholds the `GlobalAlloc::realloc` contract.
        let moved = unsafe { System.realloc(ptr, layout, new_size) };
        if !moved.is_null() {
            LIVE.fetch_sub(layout.size(), Ordering::SeqCst);
            grow(new_size);
        }
        moved
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

const TARGET_WIRE: usize = 3_999_000;
const WIRE_FACTOR_CEILING: usize = 16;

fn dummy_input(vout: u32, witness: Witness) -> TxIn {
    TxIn {
        previous_output: OutPoint {
            txid: Txid::from_raw_hash(bitcoin::hashes::Hash::all_zeros()),
            vout,
        },
        script_sig: ScriptBuf::new(),
        sequence: Sequence::MAX,
        witness,
    }
}

fn empty_output() -> TxOut {
    TxOut {
        value: Amount::ZERO,
        script_pubkey: ScriptBuf::new(),
    }
}

fn transaction(inputs: Vec<TxIn>, outputs: Vec<TxOut>) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: inputs,
        output: outputs,
    }
}

fn wire_of(txs: Vec<Transaction>) -> Vec<u8> {
    let mut block = Block {
        header: genesis_block(Network::Regtest).header,
        txdata: txs,
    };
    block.header.merkle_root = block
        .compute_merkle_root()
        .unwrap_or_else(|| panic!("block has transactions"));
    serialize(&block)
}

fn empty_item_witness(items: usize) -> Witness {
    let empty: &[u8] = &[];
    Witness::from_slice(&vec![empty; items])
}

fn dense_witness_wire() -> Vec<u8> {
    let one_item = wire_of(vec![transaction(
        vec![dummy_input(0, empty_item_witness(1))],
        vec![empty_output()],
    )]);
    let count_prefix_growth = 4;
    let items = TARGET_WIRE - one_item.len() + 1 - count_prefix_growth;
    wire_of(vec![transaction(
        vec![dummy_input(0, empty_item_witness(items))],
        vec![empty_output()],
    )])
}

fn dense_output_wire() -> Vec<u8> {
    let probe = wire_of(vec![transaction(
        vec![dummy_input(0, Witness::new())],
        Vec::new(),
    )]);
    let outputs = (TARGET_WIRE - probe.len()) / 9 - 1;
    wire_of(vec![transaction(
        vec![dummy_input(0, Witness::new())],
        vec![empty_output(); outputs],
    )])
}

fn dense_transaction_wire() -> Vec<u8> {
    let probe = wire_of(vec![transaction(
        vec![dummy_input(0, Witness::new())],
        vec![empty_output()],
    )]);
    let count = (TARGET_WIRE - 80) / (probe.len() - 81);
    let txs = (0..count)
        .map(|index| {
            let vout = u32::try_from(index).unwrap_or_else(|_| unreachable!("count fits u32"));
            transaction(
                vec![dummy_input(vout, Witness::new())],
                vec![empty_output()],
            )
        })
        .collect();
    wire_of(txs)
}

fn fixture_wire(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/testdata/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap_or_else(|error| panic!("fixture {name} must be readable: {error}"))
}

fn assert_decode_heap_stays_bounded(label: &str, wire: Vec<u8>) {
    let wire_len = wire.len();
    let baseline = LIVE.load(Ordering::SeqCst);
    let raw = Bytes::from(wire);
    PEAK.store(LIVE.load(Ordering::SeqCst), Ordering::SeqCst);
    let payload =
        BlockPayload::from_raw(raw).unwrap_or_else(|error| panic!("{label} must decode: {error}"));
    let peak = PEAK.load(Ordering::SeqCst) - baseline;
    let retained = wire_len + payload.block().retained_heap_bytes();
    let reservation = decode_reservation(wire_len);
    assert!(
        peak <= reservation && retained <= reservation,
        "{label}: peak {peak} and retained {retained} bytes must stay within decode_reservation({wire_len}) = {reservation}"
    );
    let ceiling = WIRE_FACTOR_CEILING * wire_len;
    assert!(
        peak <= ceiling,
        "{label}: decode peaked at {peak} live bytes for {wire_len} wire bytes; the independent oracle \
         allows at most {WIRE_FACTOR_CEILING}x wire because a 4_000_000 byte block must fit the 64 MiB \
         historical budget"
    );
    assert!(
        retained <= ceiling,
        "{label}: block retains {retained} bytes for {wire_len} wire bytes; the independent oracle \
         allows at most {WIRE_FACTOR_CEILING}x wire"
    );
}

#[test]
fn dense_empty_witness_items_decode_within_sixteen_times_wire() {
    assert_decode_heap_stays_bounded("empty witness items", dense_witness_wire());
}

#[test]
fn dense_empty_outputs_decode_within_sixteen_times_wire() {
    assert_decode_heap_stays_bounded("empty outputs", dense_output_wire());
}

#[test]
fn dense_minimal_transactions_decode_within_sixteen_times_wire() {
    assert_decode_heap_stays_bounded("minimal transactions", dense_transaction_wire());
}

#[test]
fn mainnet_fixture_blocks_decode_within_sixteen_times_wire() {
    for name in ["0.bin", "363731.bin"] {
        assert_decode_heap_stays_bounded(name, fixture_wire(name));
    }
}
