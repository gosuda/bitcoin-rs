//! Paired `Hash256` `Display` microbenchmark against the pre-PR bytewise formatter.
//!
//! Run with `cargo run --locked --release -p bitcoin-rs-primitives
//! --example hash_display_bench`. Samples are not a performance acceptance gate.

use std::fmt::{self, Write as _};
use std::hint::black_box;
use std::time::{Duration, Instant};

use bitcoin_rs_primitives::Hash256;

struct Bytewise<'a>(&'a Hash256);

impl fmt::Display for Bytewise<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Exact Display loop from main ff965032, benchmark-only.
        for byte in self.0.as_byte_array().iter().rev() {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

fn measure(
    hashes: &[Hash256],
    optimized: bool,
    reuse: bool,
    iterations: usize,
) -> Result<Duration, fmt::Error> {
    let mut output = String::with_capacity(64);
    let started = Instant::now();
    for hash in hashes.iter().cycle().take(iterations) {
        let hash = black_box(hash);
        if reuse {
            output.clear();
            if optimized {
                write!(&mut output, "{hash}")?;
            } else {
                write!(&mut output, "{}", Bytewise(hash))?;
            }
            black_box(output.as_str());
        } else {
            let text = if optimized {
                hash.to_string()
            } else {
                Bytewise(hash).to_string()
            };
            black_box(text);
        }
    }
    Ok(started.elapsed())
}

fn main() -> fmt::Result {
    let release_build = !cfg!(debug_assertions);
    assert!(release_build, "run this benchmark with --release");
    let hashes: Vec<_> = (0_u8..=u8::MAX)
        .map(|seed| {
            let mut bytes = [0_u8; 32];
            for (offset, byte) in (0_u8..32).zip(&mut bytes) {
                *byte = seed.wrapping_add(offset);
            }
            Hash256::from_le_bytes(&bytes)
        })
        .collect();
    for hash in &hashes {
        assert_eq!(hash.to_string(), Bytewise(hash).to_string());
    }
    for reuse in [true, false] {
        for optimized in [false, true] {
            let _ = measure(&hashes, optimized, reuse, 10_000)?;
        }
        for sample in 0..7 {
            for optimized in [sample % 2 != 0, sample % 2 == 0] {
                let iterations = 100_000;
                let elapsed_ns = measure(&hashes, optimized, reuse, iterations)?.as_nanos();
                println!(
                    "hash_sample,reuse={reuse},optimized={optimized},sample={sample},iterations={iterations},elapsed_ns={elapsed_ns}"
                );
            }
        }
    }
    Ok(())
}
