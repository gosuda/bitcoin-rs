use std::hint::black_box;

use bitcoin::hashes::Hash;
use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin::p2p::message_filter::CFilter;
use bitcoin_rs_p2p::wire::{Message, PeerError, encode_payload, wire_len};

#[cfg(count_allocations)]
mod heap {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::cell::Cell;

    #[derive(Clone, Copy, Default)]
    pub struct Stats {
        pub allocated: usize,
        pub allocations: usize,
        pub live: usize,
        pub peak: usize,
    }

    thread_local! {
        static ACTIVE: Cell<Option<Stats>> = const { Cell::new(None) };
    }

    fn allocated(old_size: usize, new_size: usize) {
        let _ = ACTIVE.try_with(|active| {
            if let Some(mut stats) = active.get() {
                stats.allocated += new_size;
                stats.allocations += 1;
                stats.live = stats.live - old_size + new_size;
                stats.peak = stats.peak.max(stats.live);
                active.set(Some(stats));
            }
        });
    }

    struct CountingAllocator;

    // SAFETY: every operation forwards the caller's pointer and layout unchanged to System.
    unsafe impl GlobalAlloc for CountingAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            // SAFETY: the caller supplies a valid allocation layout.
            let pointer = unsafe { System.alloc(layout) };
            if !pointer.is_null() {
                allocated(0, layout.size());
            }
            pointer
        }

        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            // SAFETY: the caller supplies a valid allocation layout.
            let pointer = unsafe { System.alloc_zeroed(layout) };
            if !pointer.is_null() {
                allocated(0, layout.size());
            }
            pointer
        }

        unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
            let _ = ACTIVE.try_with(|active| {
                if let Some(mut stats) = active.get() {
                    stats.live -= layout.size();
                    active.set(Some(stats));
                }
            });
            // SAFETY: the caller supplies a live allocation and its matching layout.
            unsafe { System.dealloc(pointer, layout) };
        }

        unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
            // SAFETY: the caller supplies a live allocation and a valid replacement size.
            let moved = unsafe { System.realloc(pointer, layout, new_size) };
            if !moved.is_null() {
                allocated(layout.size(), new_size);
            }
            moved
        }
    }

    #[global_allocator]
    static ALLOCATOR: CountingAllocator = CountingAllocator;

    pub fn measure<T>(operation: impl FnOnce() -> T) -> (T, Stats) {
        ACTIVE.set(Some(Stats::default()));
        let result = operation();
        let Some(stats) = ACTIVE.replace(None) else {
            unreachable!("allocation observation stays active until the operation returns");
        };
        (result, stats)
    }
}

#[inline]
fn queued_encode(message: &Message) -> Result<(usize, Vec<u8>), PeerError> {
    let wire_bytes = wire_len(black_box(message))?;
    let payload = encode_payload(black_box(message))?;
    Ok(black_box((wire_bytes, payload)))
}

#[cfg(count_allocations)]
fn run(name: &str, message: &Message, expected_payload: usize) -> Result<(), PeerError> {
    let (result, stats) = heap::measure(|| queued_encode(message));
    let (wire_bytes, payload) = result?;
    assert_eq!(payload.len(), expected_payload);
    assert_eq!(wire_bytes, expected_payload + 24);
    assert_eq!(stats.live, payload.capacity());
    println!(
        "{name},{},{wire_bytes},{},{},{},{},{}",
        payload.len(),
        payload.capacity(),
        stats.allocations,
        stats.allocated,
        stats.peak,
        stats.live,
    );
    Ok(())
}

#[cfg(not(count_allocations))]
fn run(name: &str, message: &Message, expected_payload: usize) -> Result<(), PeerError> {
    use std::time::Instant;

    let (wire_bytes, payload) = queued_encode(message)?;
    assert_eq!(payload.len(), expected_payload);
    assert_eq!(wire_bytes, expected_payload + 24);
    let output_capacity = payload.capacity();
    drop(payload);

    const WARMUP: u32 = 32;
    const TARGET_SAMPLE_NS: u128 = 50_000_000;
    let warmup = Instant::now();
    for _ in 0..WARMUP {
        black_box(queued_encode(message)?);
    }
    let warmup_ns = (warmup.elapsed().as_nanos() / u128::from(WARMUP)).max(1);
    let iterations = u32::try_from((TARGET_SAMPLE_NS / warmup_ns).clamp(16, 2_000_000))
        .expect("bounded calibration fits u32");

    let mut elapsed_ns = [0u128; 9];
    for sample in &mut elapsed_ns {
        let start = Instant::now();
        for _ in 0..iterations {
            black_box(queued_encode(message)?);
        }
        *sample = start.elapsed().as_nanos();
    }
    let mut ordered = elapsed_ns;
    ordered.sort_unstable();
    print!("{name},{expected_payload},{wire_bytes},{output_capacity},{iterations}");
    for sample in elapsed_ns {
        print!(",{sample}");
    }
    println!(
        ",{},{},{}",
        ordered[0] / u128::from(iterations),
        ordered[4] / u128::from(iterations),
        ordered[8] / u128::from(iterations),
    );
    Ok(())
}

fn main() -> Result<(), PeerError> {
    #[cfg(count_allocations)]
    println!(
        "workload,payload_bytes,wire_bytes,output_capacity,allocation_calls,allocated_bytes,peak_live_bytes,retained_bytes"
    );
    #[cfg(not(count_allocations))]
    println!(
        "workload,payload_bytes,wire_bytes,output_capacity,iterations_per_sample,sample_1_elapsed_ns,sample_2_elapsed_ns,sample_3_elapsed_ns,sample_4_elapsed_ns,sample_5_elapsed_ns,sample_6_elapsed_ns,sample_7_elapsed_ns,sample_8_elapsed_ns,sample_9_elapsed_ns,min_ns_per_op,median_ns_per_op,max_ns_per_op"
    );

    let hash = bitcoin::BlockHash::from_byte_array([7; 32]);
    for (name, entries, expected_payload) in [
        ("inventory_0", 0, 1),
        ("inventory_1", 1, 1 + 36),
        ("inventory_1000", 1_000, 3 + 1_000 * 36),
        ("inventory_50000", 50_000, 3 + 50_000 * 36),
    ] {
        let message = Message::Inv(vec![Inventory::Block(hash); entries]);
        run(name, &message, expected_payload)?;
    }

    let message = Message::CFilter(CFilter {
        filter_type: 0,
        block_hash: hash,
        filter: vec![0x2a; 100_000],
    });
    run("compact_filter_100000", &message, 1 + 32 + 5 + 100_000)
}
