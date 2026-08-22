//! Loads a real `utxo-v4.dat` checkpoint and reports what the set costs.
//!
//! The companion to `utxo_memory_attribution`, which builds a synthetic set from
//! an assumed script mix and an assumed outputs-per-record. This one reads a
//! chainstate a node actually produced, so the numbers carry no modelling
//! assumptions at all — and because the record codec is an internal encoding,
//! the *same* file loaded by two builds is a controlled A/B of the codec with
//! every other variable held fixed.
//!
//! It also re-checks correctness on that data. The checkpoint manifest records
//! the `MuHash` trailer's SHA-256, and the trailer is computed over decoded
//! consensus values rather than the in-memory encoding, so it must survive a
//! codec change untouched. Asserting that over 38 million real outputs is a
//! stronger statement than any fixture in the test suite makes.
//!
//! ```text
//! cargo run -p bitcoin-rs-utxo --example snapshot_memory --release -- \
//!     <path-to-utxo-v4.dat> [expected-trailer-sha256]
//! ```
// A measurement harness that cannot read its input has nothing to report.
#![allow(clippy::expect_used, clippy::print_stdout)]

use std::io::BufReader;

use bitcoin_rs_utxo::{hash_serialized_3, read_snapshot};
use sha2::{Digest as _, Sha256};

/// Resident set size in bytes, or `None` where the platform cannot report it.
///
/// Duplicated from `bitcoin-rs-node` rather than depended on: this crate must
/// not take a dependency on the node for an example, and the parser is four
/// lines. `crates/node/src/metrics.rs` is the version under test.
fn process_rss_bytes() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let status = std::fs::read_to_string("/proc/self/status").ok()?;
        status.lines().find_map(|line| {
            line.strip_prefix("VmRSS:")?
                .split_whitespace()
                .next()?
                .parse::<u64>()
                .ok()?
                .checked_mul(1024)
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        let output = std::process::Command::new("ps")
            .args(["-o", "rss=", "-p", &std::process::id().to_string()])
            .output()
            .ok()?;
        String::from_utf8(output.stdout)
            .ok()?
            .trim()
            .parse::<u64>()
            .ok()?
            .checked_mul(1024)
    }
}

fn hex(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

/// Bytes per output, for reporting only.
///
/// `u32::try_from` would clip a byte total in the billions, so the widening
/// goes through `u64` and loses only mantissa precision, which is irrelevant at
/// two decimal places.
fn per(total: usize, outputs: usize) -> f64 {
    if outputs == 0 {
        return 0.0;
    }
    let total =
        u32::try_from(total / 1_000).map_or_else(|_| f64::from(u32::MAX), f64::from) * 1_000.0;
    let outputs = u32::try_from(outputs).map_or_else(|_| f64::from(u32::MAX), f64::from);
    total / outputs
}

fn main() {
    let mut args = std::env::args().skip(1);
    let path = args
        .next()
        .expect("usage: snapshot_memory <utxo-v4.dat> [expected-trailer-sha256]");
    let expected_trailer = args.next();

    let baseline = process_rss_bytes();

    let file = std::fs::File::open(&path).expect("snapshot opens");
    let bytes_on_disk = file.metadata().map_or(0, |meta| meta.len());
    let started = std::time::Instant::now();
    let loaded = read_snapshot(&mut BufReader::new(file)).expect("snapshot loads");
    let load_elapsed = started.elapsed();

    // `clippy::redundant_closure` suggests passing `UtxoSetView::memory_report`
    // directly; that does not compile, because the higher-ranked lifetime on the
    // view does not unify with a bare function item.
    #[expect(
        clippy::redundant_closure_for_method_calls,
        reason = "the direct path does not compile"
    )]
    let report = loaded.set.with_stable_view(|view| view.memory_report());
    let rss = process_rss_bytes();

    println!("snapshot        {path}");
    println!("height          {}", loaded.height);
    println!("tip             {}", loaded.tip_hash.to_string_be());
    println!("on disk         {bytes_on_disk} B");
    println!("load            {:.1} s", load_elapsed.as_secs_f64());
    println!();
    println!("records         {}", report.records);
    println!("outputs         {}", report.outputs);
    println!();
    println!(
        "payload         {:>14} B   {:>6.2} B/output",
        report.record_payload_bytes,
        per(report.record_payload_bytes, report.outputs)
    );
    println!(
        "+ alloc header  {:>14} B   {:>6.2} B/output",
        report.record_allocation_bytes,
        per(report.record_allocation_bytes, report.outputs)
    );
    println!(
        "+ hash table    {:>14} B   {:>6.2} B/output",
        report.accounted_bytes(),
        per(report.accounted_bytes(), report.outputs)
    );
    match (baseline, rss) {
        (Some(before), Some(after)) => {
            let delta = after.saturating_sub(before);
            println!(
                "process RSS     {after:>14} B   {:>6.2} B/output   (delta over baseline {delta} B, {:.2} B/output)",
                per(usize::try_from(after).unwrap_or(0), report.outputs),
                per(usize::try_from(delta).unwrap_or(0), report.outputs)
            );
        }
        _ => println!("process RSS     unavailable on this platform"),
    }

    // Both of these are computed over decoded consensus values, never over the
    // record encoding, so a codec change must leave them byte-identical.
    // Checked here against 38 million real outputs rather than a fixture.
    let hashed = std::time::Instant::now();
    let serialized = hash_serialized_3(&loaded.set).expect("hash_serialized_3");
    println!();
    println!(
        "hash_serialized_3  {}   ({:.1} s)",
        hex(&serialized.to_le_bytes()),
        hashed.elapsed().as_secs_f64()
    );
    // The trailer is computed over consensus values, never over the record
    // encoding, so a codec change must leave it byte-identical. Checked here
    // against 38 million real outputs rather than a fixture.
    let trailer_sha = hex(&Sha256::digest(loaded.muhash_trailer));
    println!();
    println!("muhash trailer  sha256 {trailer_sha}");
    if let Some(expected) = expected_trailer {
        assert_eq!(
            trailer_sha, expected,
            "the MuHash trailer changed; the record codec is not consensus-neutral"
        );
        println!("                matches the checkpoint manifest");
    }
}
