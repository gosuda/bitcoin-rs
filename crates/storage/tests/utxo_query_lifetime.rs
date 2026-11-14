use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use bitcoin_rs_consensus::primitives::{Amount, Hash256, OutPoint, Script, TxOut};
use bitcoin_rs_storage::utxo::UtxoReader;
use bitcoin_rs_storage::utxo::contract::{BlockChanges, UtxoAdd};
use bitcoin_rs_storage::{CoinStore, MemoryKvStore};

struct TrackingAllocator;
static LIVE_BYTES: AtomicUsize = AtomicUsize::new(0);

// SAFETY: allocation operations delegate unchanged to System; only successful
// allocation sizes and the caller-provided deallocation sizes are counted.
unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller supplies the layout required by System.
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            LIVE_BYTES.fetch_add(layout.size(), Ordering::SeqCst);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE_BYTES.fetch_sub(layout.size(), Ordering::SeqCst);
        // SAFETY: the caller supplies a live allocation and its layout.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        // SAFETY: the caller supplies the allocation and valid new size.
        let replacement = unsafe { System.realloc(ptr, layout, size) };
        if !replacement.is_null() {
            LIVE_BYTES.fetch_add(size, Ordering::SeqCst);
            LIVE_BYTES.fetch_sub(layout.size(), Ordering::SeqCst);
        }
        replacement
    }
}

#[global_allocator]
static ALLOCATOR: TrackingAllocator = TrackingAllocator;

// ARCH-07a
#[test]
fn dropping_last_query_view_releases_derived_image_while_readers_survive()
-> Result<(), Box<dyn std::error::Error>> {
    const RECORDS: u32 = 4096;
    const SCRIPT_BYTES: usize = 512;
    let store = Arc::new(MemoryKvStore::new());
    let reader = UtxoReader::from_coin_store(Arc::new(CoinStore::open(store, 0)));
    let mut changes = BlockChanges::with_capacity(usize::try_from(RECORDS)?, 0);
    for index in 0..RECORDS {
        let mut bytes = [0_u8; 32];
        bytes[..4].copy_from_slice(&index.to_le_bytes());
        let txid = Hash256::from_le_bytes(&bytes);
        changes.add(UtxoAdd::new(
            OutPoint::new(txid.into(), index % 3),
            TxOut {
                value: Amount::from_sat(u64::from(index) + 1),
                script_pubkey: Script::from_bytes(vec![0x51; SCRIPT_BYTES]),
            },
            index % 2 == 0,
            index + 7,
        ));
    }
    reader.populate_fixture_coins(&changes)?;
    drop(changes);
    let surviving_reader = reader.clone();
    let before = LIVE_BYTES.load(Ordering::SeqCst);
    for _ in 0..2 {
        let view = reader.lock_stable_view()?;
        assert_eq!(view.len(), usize::try_from(RECORDS)?);
        assert_eq!(view.record_count(), usize::try_from(RECORDS)?);
        let mut total = 0_u64;
        for index in 0..RECORDS {
            let mut bytes = [0_u8; 32];
            bytes[..4].copy_from_slice(&index.to_le_bytes());
            let outpoint = OutPoint::new(Hash256::from_le_bytes(&bytes).into(), index % 3);
            let coin = view
                .get_entry(&outpoint)
                .ok_or("fixture coin missing from view")?;
            assert_eq!(coin.outpoint, outpoint);
            assert_eq!(coin.height, index + 7);
            assert_eq!(coin.coinbase, index % 2 == 0);
            assert_eq!(coin.txout.value.to_sat(), u64::from(index) + 1);
            assert_eq!(coin.txout.script_pubkey.as_bytes(), &[0x51; SCRIPT_BYTES]);
            total += coin.txout.value.to_sat();
        }
        assert_eq!(total, u64::from(RECORDS) * u64::from(RECORDS + 1) / 2);
        drop(view);
        let retained = LIVE_BYTES.load(Ordering::SeqCst).saturating_sub(before);
        assert!(
            retained <= 64 * 1024,
            "query image retained {retained} bytes after its last view was dropped"
        );
    }
    assert!(surviving_reader.has_live_outputs_for_txid(&Hash256::from_le_bytes(&[0; 32]))?);
    Ok(())
}
