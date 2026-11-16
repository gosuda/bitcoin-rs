#![cfg(feature = "mdbx")]

#[path = "support/error.rs"]
mod error;

use bitcoin_rs_storage::{BoundedReadError, ColumnFamily, KvStore, MdbxStore, StorageError};
use error::TestResult;
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

struct TrackingAllocator;

thread_local! {
    static LARGE_ALLOCATIONS: Cell<Option<usize>> = const { Cell::new(None) };
}

fn record(size: usize) {
    if size >= 1024 * 1024 {
        let _ = LARGE_ALLOCATIONS.try_with(|count| {
            if let Some(n) = count.get() {
                count.set(Some(n + 1));
            }
        });
    }
}

// SAFETY: every allocation operation delegates unchanged to System.
unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record(layout.size());
        // SAFETY: the caller supplies the layout required by System.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: the caller supplies a live allocation and its layout.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        record(size);
        // SAFETY: the caller supplies the allocation and valid new size.
        unsafe { System.realloc(ptr, layout, size) }
    }
}

#[global_allocator]
static ALLOCATOR: TrackingAllocator = TrackingAllocator;

// API-02
#[test]
fn bounded_read_rejects_before_value_allocation() -> TestResult {
    let dir = tempfile::tempdir()?;
    let store = MdbxStore::open(dir.path())?;
    let cf = ColumnFamily::TxConfirmed;
    let value = vec![0x5a; 2 * 1024 * 1024];
    store.put(cf, b"large", &value)?;
    store.put(cf, b"empty", b"")?;
    assert_eq!(store.get_bounded(cf, b"missing", 0)?, None);
    assert_eq!(store.get_bounded(cf, b"empty", 0)?, Some(vec![]));
    assert_eq!(
        store.get_bounded(cf, b"large", value.len())?,
        Some(value.clone())
    );
    for limit in [0, value.len() - 1] {
        LARGE_ALLOCATIONS.with(|count| count.set(Some(0)));
        let result = store.get_bounded(cf, b"large", limit);
        let Some(allocations) = LARGE_ALLOCATIONS.with(|count| count.replace(None)) else {
            return Err(
                StorageError::InvalidOperation("allocation measurement was not active").into(),
            );
        };
        assert!(matches!(
            result,
            Err(BoundedReadError::Limit { size, limit: actual })
                if size == value.len() && actual == limit
        ));
        assert_eq!(
            allocations, 0,
            "rejected value was allocated before checking its bound"
        );
    }
    Ok(())
}
