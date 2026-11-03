use std::io::Write as _;
use std::time::Duration;

const FLOOR_NS: u64 = 1_000_000_000;

const MEASURED_SAMPLES: u64 = 10;

pub(crate) fn run(row: &str, mut unit: impl FnMut() -> Duration) {
    for sample in 0..=MEASURED_SAMPLES {
        let (total_ns, unit_ns) = sample_units(&mut unit);
        print_sample(row, sample, total_ns, &unit_ns);
    }
}

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

fn driven(schedule: &[u64]) -> (u64, Vec<u64>) {
    let mut calls = 0_usize;
    sample_units(|| {
        let nanos = schedule[calls];
        calls += 1;
        Duration::from_nanos(nanos)
    })
}

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

fn push_u64(line: &mut String, value: u64) {
    use std::fmt::Write as _;
    line.write_fmt(format_args!("{value}"))
        .unwrap_or_else(|error| panic!("formatting sample integer failed: {error}"));
}
