//! Attributes UTXO-set memory: what the set can account for, versus process RSS.
//!
//! Step 2.1 of the memory campaign, and deliberately measurement only. The
//! published tip-RSS evidence reached **13.83 GiB at height 645,804** and never
//! made the tip, against a G14 budget of 16 GiB. The record encoding alone does
//! not predict that figure, and the gap has never been attributed. Changing the
//! encoding before knowing where the bytes go would repeat a mistake this
//! project's own performance notes record twice: pricing a replacement against a
//! total that includes work which does not disappear.
//!
//! Run:
//!
//! ```text
//! cargo run -p bitcoin-rs-utxo --example utxo_memory_attribution --release -- [records] [churn_rounds]
//! ```
//!
//! `churn_rounds` matters more than it looks. A monotonically inserted set never
//! frees anything, so it measures allocator size-class rounding and nothing else.
//! A real set has spent and re-created coins for every block of its history, and
//! that churn is where fragmentation comes from. Passing rounds > 0 spends a
//! slice of the set and refills it, repeatedly, holding the live count constant.
// A measurement tool: a failed fixture must abort loudly, not report a number.
#![allow(clippy::expect_used)]
#![allow(clippy::print_stdout)]

use bitcoin::{Amount, ScriptBuf};
use bitcoin_rs_primitives::{Hash256, OutPoint, TxOut};
use bitcoin_rs_utxo::{BlockChanges, UtxoAdd, UtxoMemoryReport, UtxoSet};

/// Records per commit batch, so the set is built the way a node builds it.
const BATCH_RECORDS: usize = 20_000;
/// Default record count. Large enough that per-record costs dominate the
/// process baseline, small enough to finish on a laptop.
const DEFAULT_RECORDS: usize = 2_000_000;

const fn next_u64(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    *state
}

fn fill_bytes(seed: u64, out: &mut [u8]) {
    let mut state = seed;
    for chunk in out.chunks_mut(8) {
        let draw = next_u64(&mut state).to_le_bytes();
        chunk.copy_from_slice(&draw[..chunk.len()]);
    }
}

/// Script shapes in roughly the proportion the mainnet UTXO set holds them.
///
/// The exact mix matters less than the sizes: the encoding stores the script
/// verbatim, so bytes per output track these lengths directly.
fn script_for(index: u64) -> ScriptBuf {
    let mut program = [0_u8; 32];
    fill_bytes(index, &mut program);
    match index % 10 {
        // P2WPKH, 22 bytes.
        0..=3 => {
            let mut bytes = vec![0x00, 0x14];
            bytes.extend_from_slice(&program[..20]);
            ScriptBuf::from_bytes(bytes)
        }
        // P2PKH, 25 bytes.
        4..=6 => {
            let mut bytes = vec![0x76, 0xa9, 0x14];
            bytes.extend_from_slice(&program[..20]);
            bytes.extend_from_slice(&[0x88, 0xac]);
            ScriptBuf::from_bytes(bytes)
        }
        // P2SH, 23 bytes.
        7 => {
            let mut bytes = vec![0xa9, 0x14];
            bytes.extend_from_slice(&program[..20]);
            bytes.push(0x87);
            ScriptBuf::from_bytes(bytes)
        }
        // P2TR, 34 bytes.
        _ => {
            let mut bytes = vec![0x51, 0x20];
            bytes.extend_from_slice(&program);
            ScriptBuf::from_bytes(bytes)
        }
    }
}

/// Live outputs per record, targeting a mean of `mean_x100 / 100`.
///
/// This ratio is the single assumption the attribution is most sensitive to:
/// the 32-byte txid is stored once per record and amortizes over exactly this
/// many outputs. It is therefore taken from a real chainstate
/// (`gettxoutsetinfo` reports `txouts / transactions`) rather than guessed —
/// an earlier revision assumed 1.5 and a pruned mainnet sync measured 2.30 at
/// height 183k and 3.43 at 302k.
///
/// Only the mean is reproduced, not the tail shape. The mean is what drives
/// amortization; the tail would additionally shift allocator size classes,
/// which the measured allocator overhead already folds in.
fn outputs_for(index: u64, mean_x100: u64) -> u32 {
    let base = mean_x100 / 100;
    let remainder = mean_x100 % 100;
    let extra = u64::from(index % 100 < remainder);
    let count = base + extra;
    if count == 0 {
        1
    } else {
        u32::try_from(count).unwrap_or(u32::MAX)
    }
}

/// Resident set size in bytes, or `None` where it cannot be read.
fn rss_bytes() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let status = std::fs::read_to_string("/proc/self/status").ok()?;
        for line in status.lines() {
            if let Some(value) = line.strip_prefix("VmRSS:") {
                let kib = value.split_whitespace().next()?.parse::<u64>().ok()?;
                return kib.checked_mul(1024);
            }
        }
        None
    }
    #[cfg(not(target_os = "linux"))]
    {
        // `ps` is the portable option here; this is a measurement tool, not a
        // hot path, and it avoids a platform-specific dependency for one number.
        let pid = std::process::id();
        let output = std::process::Command::new("ps")
            .args(["-o", "rss=", "-p", &pid.to_string()])
            .output()
            .ok()?;
        let kib = String::from_utf8(output.stdout)
            .ok()?
            .trim()
            .parse::<u64>()
            .ok()?;
        kib.checked_mul(1024)
    }
}

#[expect(
    clippy::as_conversions,
    clippy::cast_precision_loss,
    reason = "reporting megabytes to two decimals"
)]
fn mib(bytes: u64) -> f64 {
    bytes as f64 / (1024.0 * 1024.0)
}

#[expect(
    clippy::as_conversions,
    clippy::cast_precision_loss,
    reason = "reporting bytes per output to one decimal"
)]
fn per(bytes: u64, outputs: u64) -> f64 {
    bytes as f64 / outputs.max(1) as f64
}

/// Prints the attribution table.
fn report(report: &UtxoMemoryReport, delta: u64, churn_rounds: usize) {
    let outputs = u64::try_from(report.outputs).unwrap_or(1).max(1);
    let accounted = u64::try_from(report.accounted_bytes()).unwrap_or(0);
    let payload = u64::try_from(report.record_payload_bytes).unwrap_or(0);
    let allocation = u64::try_from(report.record_allocation_bytes).unwrap_or(0);
    let tables = u64::try_from(report.table_bytes).unwrap_or(0);

    println!("churn rounds                {churn_rounds}");
    println!("records                     {}", report.records);
    println!("outputs                     {}", report.outputs);
    println!("record payload              {:>10.2} MiB", mib(payload));
    println!("record allocations          {:>10.2} MiB", mib(allocation));
    println!("hash tables (estimated)     {:>10.2} MiB", mib(tables));
    println!("accounted total             {:>10.2} MiB", mib(accounted));
    println!("process RSS delta           {:>10.2} MiB", mib(delta));
    println!(
        "unaccounted                 {:>10.2} MiB",
        mib(delta.saturating_sub(accounted))
    );
    println!();
    println!(
        "bytes/output  payload {:>6.1}   allocation {:>6.1}   accounted {:>6.1}   RSS {:>6.1}",
        per(payload, outputs),
        per(allocation, outputs),
        per(accounted, outputs),
        per(delta, outputs),
    );
    println!(
        "RSS / accounted             {:>10.3}x",
        per(delta, accounted.max(1))
    );
}

fn main() {
    let records: usize = std::env::args()
        .nth(1)
        .and_then(|arg| arg.parse().ok())
        .unwrap_or(DEFAULT_RECORDS);
    let churn_rounds: usize = std::env::args()
        .nth(2)
        .and_then(|arg| arg.parse().ok())
        .unwrap_or(0);
    // Mean live outputs per record, x100. Default matches the 3.43 measured on
    // a pruned mainnet sync at height 302,740.
    let mean_x100: u64 = std::env::args()
        .nth(3)
        .and_then(|arg| arg.parse().ok())
        .unwrap_or(343);

    let set = UtxoSet::new();
    let baseline = rss_bytes().expect("read RSS");

    let mut index: u64 = 0;
    let mut written = 0_usize;
    while written < records {
        let batch = BATCH_RECORDS.min(records - written);
        let mut changes = BlockChanges::with_capacity(batch * 2, 0);
        for _ in 0..batch {
            let mut txid_bytes = [0_u8; 32];
            fill_bytes(index, &mut txid_bytes);
            let txid = Hash256::from_le_bytes(&txid_bytes);
            for vout in 0..outputs_for(index, mean_x100) {
                changes.add(UtxoAdd {
                    outpoint: OutPoint::new(txid, vout),
                    txout: TxOut {
                        value: Amount::from_sat(1_000 + index % 100_000),
                        script_pubkey: script_for(index.wrapping_add(u64::from(vout))),
                    },
                    coinbase: index.is_multiple_of(1_000),
                    height: u32::try_from(index % 800_000).unwrap_or(0),
                });
            }
            index += 1;
        }
        set.commit_block(&changes, &Hash256::from_le_bytes(&[0_u8; 32]))
            .expect("commit batch");
        written += batch;
    }

    // Churn: spend the oldest slice and create an equal number of fresh
    // records, so the live count holds steady while the allocator sees the
    // insert/free traffic a real chain produces.
    let churn_slice = records / 10;
    let mut spent_from: u64 = 0;
    for _ in 0..churn_rounds {
        let mut written_this_round = 0_usize;
        while written_this_round < churn_slice {
            let batch = BATCH_RECORDS.min(churn_slice - written_this_round);
            let mut changes = BlockChanges::with_capacity(batch * 2, batch * 2);
            for _ in 0..batch {
                let mut old_bytes = [0_u8; 32];
                fill_bytes(spent_from, &mut old_bytes);
                let old_txid = Hash256::from_le_bytes(&old_bytes);
                for vout in 0..outputs_for(spent_from, mean_x100) {
                    changes.remove(OutPoint::new(old_txid, vout));
                }
                spent_from += 1;

                let mut new_bytes = [0_u8; 32];
                fill_bytes(index, &mut new_bytes);
                let new_txid = Hash256::from_le_bytes(&new_bytes);
                for vout in 0..outputs_for(index, mean_x100) {
                    changes.add(UtxoAdd {
                        outpoint: OutPoint::new(new_txid, vout),
                        txout: TxOut {
                            value: Amount::from_sat(1_000 + index % 100_000),
                            script_pubkey: script_for(index.wrapping_add(u64::from(vout))),
                        },
                        coinbase: false,
                        height: u32::try_from(index % 800_000).unwrap_or(0),
                    });
                }
                index += 1;
            }
            set.commit_block(&changes, &Hash256::from_le_bytes(&[1_u8; 32]))
                .expect("commit churn batch");
            written_this_round += batch;
        }
    }

    // Clippy suggests passing `UtxoSetView::memory_report` directly here; that
    // does not compile, because `with_stable_view` needs a closure general over
    // the view's lifetime and a method reference is not.
    #[allow(clippy::redundant_closure_for_method_calls)]
    let memory = set.with_stable_view(|view| view.memory_report());
    let after = rss_bytes().expect("read RSS");
    report(&memory, after.saturating_sub(baseline), churn_rounds);
}
