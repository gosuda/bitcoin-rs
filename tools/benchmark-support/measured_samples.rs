//! Counted benchmark sampling shared by the MRP control benches.
//!
//! Replaces Criterion's wall-time iteration sizing for rows whose untimed
//! setup or teardown would otherwise sit inside Criterion's warm-up window:
//! one whole semantic unit per callback call, accumulated measured work to
//! the acceptance raw floor, then one warmup sample followed by ten measured
//! samples per invocation.
//!
//! Contract: `docs/benchmarks/measured-campaign.md#counted-samples`.
//! - `run` executes exactly one whole semantic unit per callback call; the
//!   callback returns that unit's measured `Duration`. The warmup sample uses
//!   the same one-second measured-work rule and is excluded from statistics
//!   downstream.
//! - Durations are exact nonnegative u64 nanoseconds folded with checked
//!   addition; the unit loop stops on the first completed unit whose sum
//!   reaches `FLOOR_NS`. Zero individual durations are legal; the total must
//!   be positive and the count nonzero. Nothing divides or rounds.
//! - Each sample is one JSON object on a line prefixed `MRP_COUNTED_SAMPLE `
//!   (prefix plus one ASCII space) with exactly the keys `bench` (full row
//!   ID), `sample` (0..=10), `warmup` (true only for index 0), `unit_ns`
//!   (nonnegative integers), `unit_count` (exact array length) and
//!   `total_ns` (exact sum). No redundant mean, no console-duration parsing,
//!   no clock clamps; auxiliary fixture diagnostics live on other lines.
//!
//! Each bench includes this file by the relative
//! `#[path = "../../../tools/benchmark-support/measured_samples.rs"]` module,
//! so identical bytes ship in every control. The module is the counted
//! protocol's printer for those bench binaries: sample lines are its only
//! output, and `verify_stopping_rule` never emits sample records.

use std::io::Write as _;
use std::time::Duration;

/// Measured-work floor per sample: one second of accumulated unit time, the
/// existing acceptance raw floor.
const FLOOR_NS: u64 = 1_000_000_000;

/// Measured samples per invocation (indices 1..=10; index 0 is the warmup).
const MEASURED_SAMPLES: u64 = 10;

/// Counted sampling for one row: one warmup sample plus ten measured samples,
/// each one second of accumulated measured whole-unit time. The callback must
/// execute exactly one whole semantic unit per call and return its measured
/// duration; setup, teardown and identity assertions keep their existing
/// sides of the unit's timer.
pub(crate) fn run(row: &str, mut unit: impl FnMut() -> Duration) {
    for sample in 0..=MEASURED_SAMPLES {
        let (total_ns, unit_ns) = sample_units(&mut unit);
        print_sample(row, sample, total_ns, &unit_ns);
    }
}

/// Deterministic untimed verification of the counted stopping rule: zero
/// durations, exact-floor stopping, and overshoot, with no sample records.
///
/// The harness supplies the unit durations directly, so the assertions hold
/// on the exact contract inputs, not on wall-clock samples. The returned
/// per-unit vector proves both the stop point (its length) and the retained
/// overshoot surplus (its sum); real workloads are not assumed to land the
/// total exactly on the floor.
pub(crate) fn verify_stopping_rule() {
    let (total, units) = driven(&[0, 0, 0, FLOOR_NS]);
    assert_eq!(
        units,
        [0, 0, 0, FLOOR_NS],
        "zero durations must not stop the unit loop before the floor"
    );
    assert_eq!(
        total, FLOOR_NS,
        "the crossing unit must supply the whole total"
    );

    let (total, units) = driven(&[FLOOR_NS]);
    assert_eq!(
        units,
        [FLOOR_NS],
        "a unit landing exactly on the floor must stop the loop"
    );
    assert_eq!(total, FLOOR_NS, "the floor alone must satisfy the stop");

    let (total, units) = driven(&[FLOOR_NS / 2, FLOOR_NS]);
    assert_eq!(
        units,
        [FLOOR_NS / 2, FLOOR_NS],
        "overshoot must stop on the crossing unit"
    );
    assert_eq!(
        total,
        FLOOR_NS + FLOOR_NS / 2,
        "the overshoot surplus must be retained, never trimmed"
    );
}

/// Drives the shared accumulation loop with a deterministic unit schedule and
/// returns `(total_ns, unit_ns)`; the schedule index panics if the loop
/// consumes more entries than supplied.
fn driven(schedule: &[u64]) -> (u64, Vec<u64>) {
    let mut calls = 0_usize;
    sample_units(|| {
        let nanos = schedule[calls];
        calls += 1;
        Duration::from_nanos(nanos)
    })
}

/// Accumulates whole units until the accumulated measured time reaches the
/// acceptance raw floor on a completed unit; returns `(total_ns, unit_ns)`
/// with the exact per-unit nanoseconds in call order. Serialization consumes
/// the returned checked total, so the units are traversed exactly once.
fn sample_units(mut unit: impl FnMut() -> Duration) -> (u64, Vec<u64>) {
    let mut unit_ns = Vec::new();
    let mut total_ns = 0_u64;
    loop {
        let duration = unit();
        let nanos = u64::try_from(duration.as_nanos())
            .unwrap_or_else(|error| panic!("unit duration exceeds u64 nanoseconds: {error}"));
        total_ns = total_ns
            .checked_add(nanos)
            .unwrap_or_else(|| panic!("accumulated unit duration exceeds u64 nanoseconds"));
        unit_ns.push(nanos);
        if total_ns >= FLOOR_NS {
            break;
        }
    }
    debug_assert!(!unit_ns.is_empty(), "the floor forces a nonzero unit count");
    debug_assert!(total_ns > 0, "the floor forces a positive total");
    (total_ns, unit_ns)
}

/// Serializes and emits one counted sample line: `MRP_COUNTED_SAMPLE` prefix
/// plus one ASCII space, exact JSON keys in contract order, no extra fields,
/// no mean, no clamping. `total_ns` is the already-checked accumulation from
/// `sample_units`; serialization does not re-traverse the units.
fn print_sample(row: &str, sample: u64, total_ns: u64, unit_ns: &[u64]) {
    let mut line = String::with_capacity(96 + unit_ns.len() * 21);
    line.push_str("MRP_COUNTED_SAMPLE {\"bench\":\"");
    line.push_str(row);
    line.push_str("\",\"sample\":");
    push_u64(&mut line, sample);
    line.push_str(if sample == 0 {
        ",\"warmup\":true"
    } else {
        ",\"warmup\":false"
    });
    line.push_str(",\"unit_ns\":[");
    for (position, &ns) in unit_ns.iter().enumerate() {
        if position > 0 {
            line.push(',');
        }
        push_u64(&mut line, ns);
    }
    line.push_str("],\"unit_count\":");
    push_u64(
        &mut line,
        u64::try_from(unit_ns.len())
            .unwrap_or_else(|error| panic!("unit count exceeds u64: {error}")),
    );
    line.push_str(",\"total_ns\":");
    push_u64(&mut line, total_ns);
    line.push('}');
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(line.as_bytes())
        .and_then(|()| stdout.write_all(b"\n"))
        .unwrap_or_else(|error| panic!("counted sample line write failed: {error}"));
}

/// Appends the exact decimal digits of `value`; u64 input makes every digit
/// exact.
fn push_u64(line: &mut String, value: u64) {
    use std::fmt::Write as _;
    line.write_fmt(format_args!("{value}"))
        .unwrap_or_else(|error| panic!("formatting sample integer failed: {error}"));
}
