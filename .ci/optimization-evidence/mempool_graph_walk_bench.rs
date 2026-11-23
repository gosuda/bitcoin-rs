use std::sync::Arc;

use bitcoin_rs_consensus::primitives::{
    Amount, Hash256, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid, Witness,
};
use bitcoin_rs_mempool::{EntryId, Mempool, MempoolEntry, MempoolError, MempoolLimits};

#[cfg(count_allocations)]
mod heap {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::cell::Cell;

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

    pub fn measure<T>(walk: impl FnOnce() -> T) -> (T, usize) {
        ALLOCATED.set(Some(0));
        let result = walk();
        let Some(bytes) = ALLOCATED.replace(None) else {
            unreachable!("allocation measurement must be active until the walk returns");
        };
        (result, bytes)
    }
}

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

#[inline]
fn walk(pool: &Mempool, id: EntryId, ancestors: bool) -> Vec<EntryId> {
    if ancestors {
        std::hint::black_box(pool).ancestor_ids_for_entry(std::hint::black_box(id))
    } else {
        std::hint::black_box(pool).descendant_ids_for_entry(std::hint::black_box(id))
    }
}

#[cfg(count_allocations)]
fn measure(pool: &Mempool, name: &str, id: EntryId, ancestors: bool, expected_len: usize) {
    let (result, allocated) = heap::measure(|| walk(pool, id, ancestors));
    assert_eq!(result.len(), expected_len);
    println!("{name},{expected_len},{allocated}");
}

#[cfg(not(count_allocations))]
fn measure(pool: &Mempool, name: &str, id: EntryId, ancestors: bool, expected_len: usize) {
    use std::hint::black_box;
    use std::time::Instant;

    let result = walk(pool, id, ancestors);
    assert_eq!(result.len(), expected_len);
    drop(result);

    const WARMUP: u32 = 1_000;
    const TARGET_SAMPLE_NS: u128 = 50_000_000;
    let warmup = Instant::now();
    for _ in 0..WARMUP {
        black_box(walk(pool, id, ancestors));
    }
    let warmup_ns = (warmup.elapsed().as_nanos() / u128::from(WARMUP)).max(1);
    let iterations = u32::try_from((TARGET_SAMPLE_NS / warmup_ns).clamp(16, 2_000_000))
        .expect("bounded calibration fits u32");

    let mut elapsed_ns = [0u128; 9];
    for sample in &mut elapsed_ns {
        let start = Instant::now();
        for _ in 0..iterations {
            black_box(walk(pool, id, ancestors));
        }
        *sample = start.elapsed().as_nanos();
    }
    let mut ordered = elapsed_ns;
    ordered.sort_unstable();
    print!("{name},{expected_len},{iterations}");
    for sample in elapsed_ns {
        print!(",{sample}");
    }
    println!(
        ",{},{},{}",
        ordered[0] / u128::from(iterations),
        ordered[4] / u128::from(iterations),
        ordered[8] / u128::from(iterations),
    );
}

fn fixture(unrelated: u32, chain: usize) -> Result<(Mempool, EntryId, EntryId), ProofError> {
    let mut pool = Mempool::new(MempoolLimits::default());
    for serial in 0..unrelated {
        insert(&mut pool, external_outpoint(serial))?;
    }
    let (mut txid, first) = insert(&mut pool, external_outpoint(unrelated))?;
    let mut last = first;
    for _ in 1..chain {
        (txid, last) = insert(&mut pool, OutPoint::new(txid, 0))?;
    }
    Ok((pool, first, last))
}

fn main() -> Result<(), ProofError> {
    #[cfg(count_allocations)]
    println!("workload,returned_vertices,allocated_bytes");
    #[cfg(not(count_allocations))]
    println!(
        "workload,returned_vertices,iterations_per_sample,sample_1_elapsed_ns,sample_2_elapsed_ns,sample_3_elapsed_ns,sample_4_elapsed_ns,sample_5_elapsed_ns,sample_6_elapsed_ns,sample_7_elapsed_ns,sample_8_elapsed_ns,sample_9_elapsed_ns,min_ns_per_op,median_ns_per_op,max_ns_per_op"
    );
    for (name, unrelated, chain) in [
        ("low_id_pair", 0, 2),
        ("high_id_pair", 16_384, 2),
        ("low_id_chain25", 0, 25),
        ("high_id_chain25", 16_384, 25),
        ("low_id_chain64", 0, 64),
        ("high_id_chain64", 16_384, 64),
    ] {
        let (pool, first, last) = fixture(unrelated, chain)?;
        measure(&pool, &format!("{name}_ancestors"), last, true, chain - 1);
        measure(
            &pool,
            &format!("{name}_descendants"),
            first,
            false,
            chain - 1,
        );
    }
    Ok(())
}
