use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::Arc;

use bitcoin_rs_consensus::primitives::{
    Amount, Hash256, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid, Witness,
};
use bitcoin_rs_mempool::{EntryId, Mempool, MempoolEntry, MempoolError, MempoolLimits};

struct CountingAllocator;

thread_local! {
    static ALLOCATED: Cell<Option<usize>> = const { Cell::new(None) };
}

fn record(size: usize) {
    let _ = ALLOCATED.try_with(|allocated| {
        if let Some(total) = allocated.get() {
            allocated.set(Some(total + size));
        }
    });
}

// SAFETY: every operation forwards the caller's pointer and layout unchanged to System.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller supplies a valid allocation layout.
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            record(layout.size());
        }
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller supplies a valid allocation layout.
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() {
            record(layout.size());
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: the caller supplies a live allocation and its matching layout.
        unsafe { System.dealloc(ptr, layout) };
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: the caller supplies a live allocation and a valid replacement size.
        let next = unsafe { System.realloc(ptr, layout, new_size) };
        if !next.is_null() {
            record(new_size);
        }
        next
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

#[derive(Debug, thiserror::Error)]
enum ProofError {
    #[error(transparent)]
    Mempool(#[from] MempoolError),
    #[error(transparent)]
    Integer(#[from] std::num::TryFromIntError),
    #[error("inserted transaction has no entry id")]
    MissingEntry,
}

fn external_outpoint(serial: u32) -> OutPoint {
    let mut bytes = [0x2a; 32];
    bytes[..4].copy_from_slice(&serial.to_le_bytes());
    OutPoint::new(Txid(Hash256::from_le_bytes(&bytes)), 0)
}

fn insert(pool: &mut Mempool, previous_output: OutPoint) -> Result<(Txid, EntryId), ProofError> {
    let tx = Arc::new(Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output,
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: vec![0x51].into(),
        }],
        lock_time: LockTime::ZERO,
    });
    let txid = tx.txid();
    let vsize = u32::try_from(tx.vsize())?;
    pool.insert_entry(MempoolEntry::new(tx, vsize, 1_000, 0, 0, 0))?;
    let id = pool
        .entry_id_by_txid(&txid)
        .ok_or(ProofError::MissingEntry)?;
    Ok((txid, id))
}

fn measured<T>(walk: impl FnOnce() -> T) -> (T, usize) {
    ALLOCATED.set(Some(0));
    let result = walk();
    let Some(bytes) = ALLOCATED.replace(None) else {
        unreachable!("allocation measurement must be active until the walk returns");
    };
    (result, bytes)
}

// POL-05
#[test]
fn local_graph_walk_allocation_ignores_unrelated_entries() -> Result<(), ProofError> {
    const UNRELATED: u32 = 4_096;
    const TWO_VERTEX_WALK_BYTES: usize = 256;

    let mut pool = Mempool::new(MempoolLimits::default());
    for serial in 0..UNRELATED {
        insert(&mut pool, external_outpoint(serial))?;
    }
    let (parent_txid, parent) = insert(&mut pool, external_outpoint(UNRELATED))?;
    let (_, child) = insert(&mut pool, OutPoint::new(parent_txid, 0))?;
    assert!(parent >= UNRELATED && child > parent);

    let (ancestors, ancestor_bytes) = measured(|| pool.ancestor_ids_for_entry(child));
    let (descendants, descendant_bytes) = measured(|| pool.descendant_ids_for_entry(parent));
    assert_eq!(ancestors, [parent]);
    assert_eq!(descendants, [child]);
    println!(
        "unrelated_entries={UNRELATED} ancestor_allocated_bytes={ancestor_bytes} \
         descendant_allocated_bytes={descendant_bytes}"
    );
    assert!(
        ancestor_bytes <= TWO_VERTEX_WALK_BYTES,
        "ancestor storage must follow the visited graph, not unrelated entry ids: {ancestor_bytes} bytes"
    );
    assert!(
        descendant_bytes <= TWO_VERTEX_WALK_BYTES,
        "descendant storage must follow the visited graph, not unrelated entry ids: {descendant_bytes} bytes"
    );
    Ok(())
}
