use std::{
    hint::black_box,
    time::{Duration, Instant},
};

use bitcoin_rs_chain::adaptive_difficulty::{DifficultyController, U256, WINDOW_SIZE};

const WARMUP_ITERS: u64 = 100_000;
const MIN_MEASURE: Duration = Duration::from_secs(12);

fn seeded_controller() -> DifficultyController {
    let mut controller = DifficultyController::new();
    for height in 0..WINDOW_SIZE {
        let timestamp =
            u32::try_from(height * 600).unwrap_or_else(|_| unreachable!("timestamp fits u32"));
        controller.push_timestamp(timestamp);
    }
    controller
}

fn run_once(mut controller: DifficultyController, iterations: u64) -> (U256, u64) {
    let mut target = U256([0x0000_ffff_ffff_ffff, 0x0000_0000_ffff_ffff, 0, 0]);
    let mut timestamp =
        u32::try_from(WINDOW_SIZE * 600).unwrap_or_else(|_| unreachable!("timestamp fits u32"));

    for step in 0..iterations {
        let jitter =
            u32::try_from(step & 0x1f).unwrap_or_else(|_| unreachable!("masked step fits u32"));
        timestamp = timestamp.wrapping_add(590 + jitter);
        controller.push_timestamp(black_box(timestamp));
        target = controller.next_target(black_box(target));
    }

    (target, iterations)
}

fn main() {
    let controller = seeded_controller();
    let _ = black_box(run_once(controller.clone(), WARMUP_ITERS));

    let mut iterations = 1_000_000_u64;
    loop {
        let start = Instant::now();
        let (target, completed) = run_once(controller.clone(), iterations);
        let elapsed = start.elapsed();
        if elapsed >= MIN_MEASURE {
            let ns_per_iter = elapsed.as_nanos() as f64 / completed as f64;
            let iter_per_sec = completed as f64 / elapsed.as_secs_f64();
            println!("iterations={completed}");
            println!("elapsed_ns={}", elapsed.as_nanos());
            println!("ns_per_iter={ns_per_iter:.3}");
            println!("iter_per_sec={iter_per_sec:.3}");
            println!("target={target:?}");
            break;
        }
        iterations = iterations.saturating_mul(2);
    }
}
