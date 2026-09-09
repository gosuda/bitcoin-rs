//! HPA-12 — a measurement without its identity is not evidence.
//!
//! Every sample in the hot-path ledger names the binary, configuration,
//! corpus, backend, durability and hardware it ran under. The ledger refuses
//! a sample that lacks any of them, refuses to add intervals that share
//! instants, and keeps every repeated sample and every empty cell: schema
//! validity is the floor, never a product result.

#![expect(
    clippy::expect_used,
    reason = "fixtures assert typed rejections by construction"
)]

use bitcoin_rs_node::metrics::{
    Cell, CorpusIdentity, EvidenceError, EvidenceIdentity, Interval, IntervalKind, LEDGER_SCHEMA,
    Ledger, Sample, Sha256Hex,
};

const LEDGER_TOML: &str = include_str!("../../../docs/benchmarks/hot-path-ledger.toml");
const CELL: &str = "offline.c150.x86_64.fjall";

fn identity() -> EvidenceIdentity {
    EvidenceIdentity {
        binary_sha256: Sha256Hex([0x11; 32]),
        version: "0.4.0".into(),
        config_sha256: Sha256Hex([0x22; 32]),
        corpus: Some(CorpusIdentity {
            id: "C150".into(),
            manifest_sha256: Sha256Hex([0x33; 32]),
        }),
        backend: "fjall".into(),
        durability: "journal:500b/5s".into(),
        hardware: "test x1".into(),
    }
}

fn sample(start_ns: u64, end_ns: u64) -> Sample {
    Sample {
        path: "cell.wall".into(),
        owner: "node".into(),
        identity: identity(),
        interval: Interval {
            kind: IntervalKind::Inside,
            start_ns,
            end_ns,
        },
        cpu_ns: Some(end_ns - start_ns),
        elapsed_ns: end_ns - start_ns,
        rss_peak_bytes: Some(1 << 20),
        io_bytes: Some(4096),
        storage_bytes: Some(1 << 30),
    }
}

/// Renders one measured cell and drops the line that carries `field`.
fn ledger_without(field: &str) -> String {
    let mut ledger = Ledger::parse(LEDGER_TOML).expect("checked-in ledger");
    ledger.record(CELL, sample(0, 10)).expect("record");
    let rendered = ledger.render().expect("render");
    let kept: Vec<&str> = rendered
        .lines()
        .filter(|line| !line.trim_start().starts_with(field))
        .collect();
    assert!(kept.len() < rendered.lines().count(), "{field} was present");
    kept.join("\n")
}

#[test]
fn checked_in_ledger_declares_every_cell_unmeasured() {
    let ledger = Ledger::parse(LEDGER_TOML).expect("checked-in ledger");
    assert_eq!(ledger.schema, LEDGER_SCHEMA);
    assert_eq!(ledger.cells.len(), 36);
    assert!(ledger.cells.iter().all(|cell| cell.samples.is_empty()));
}

#[test]
fn evidence_without_an_identity_is_refused() {
    for field in [
        "binary_sha256",
        "config_sha256",
        "backend",
        "durability",
        "hardware",
        "manifest_sha256",
    ] {
        let error = Ledger::parse(&ledger_without(field)).expect_err(field);
        assert!(
            matches!(error, EvidenceError::Schema(_)),
            "{field}: {error}"
        );
    }
    // A corpus table is optional to the type and mandatory to the ledger.
    let error = Ledger::parse(&ledger_without("[cells.samples.identity.corpus]"))
        .expect_err("corpus-less sample");
    assert!(
        matches!(
            error,
            EvidenceError::Schema(_) | EvidenceError::MissingCorpus
        ),
        "{error}"
    );
    let mut ledger = Ledger::parse(LEDGER_TOML).expect("checked-in ledger");
    let mut headless = sample(0, 10);
    headless.identity.corpus = None;
    assert_eq!(
        ledger.record(CELL, headless),
        Err(EvidenceError::MissingCorpus)
    );
}

#[test]
fn placeholder_digests_never_parse() {
    assert!("unmeasured".parse::<Sha256Hex>().is_err());
    assert!("1".repeat(63).parse::<Sha256Hex>().is_err());
    assert!("A".repeat(64).parse::<Sha256Hex>().is_err());
    assert_eq!(
        "11".repeat(32).parse::<Sha256Hex>(),
        Ok(Sha256Hex([0x11; 32]))
    );
}

#[test]
fn nested_and_concurrent_intervals_are_not_addends() {
    let outer = sample(0, 100);
    let nested = sample(10, 20);
    let concurrent = sample(90, 150);
    let disjoint = sample(100, 150);
    assert!(matches!(
        outer.sum(&nested),
        Err(EvidenceError::OverlappingIntervals(..))
    ));
    assert!(matches!(
        outer.sum(&concurrent),
        Err(EvidenceError::OverlappingIntervals(..))
    ));
    let total = outer.sum(&disjoint).expect("disjoint intervals add");
    assert_eq!(total.elapsed_ns, 150);
    assert_eq!(total.cpu_ns, Some(150));
    assert_eq!(total.rss_peak_bytes, Some(1 << 20));
    assert_eq!(total.interval.end_ns, 150);

    let mut unmeasured_cpu = disjoint.clone();
    unmeasured_cpu.cpu_ns = None;
    assert_eq!(
        outer.sum(&unmeasured_cpu),
        Err(EvidenceError::MismatchedTreatment)
    );
    let mut other_build = disjoint;
    other_build.identity.binary_sha256 = Sha256Hex([0x44; 32]);
    assert_eq!(
        outer.sum(&other_build),
        Err(EvidenceError::MismatchedTreatment)
    );
}

#[test]
fn repeated_samples_and_empty_cells_survive_a_round_trip() {
    let mut ledger = Ledger::parse(LEDGER_TOML).expect("checked-in ledger");
    ledger.record(CELL, sample(0, 10)).expect("first run");
    ledger
        .record(CELL, sample(0, 10))
        .expect("identical second run");
    assert_eq!(
        ledger.record("offline.c150.x86_64.leveldb", sample(0, 10)),
        Err(EvidenceError::UnknownCell(
            "offline.c150.x86_64.leveldb".into()
        ))
    );

    let reparsed = Ledger::parse(&ledger.render().expect("render")).expect("round trip");
    assert_eq!(reparsed, ledger);
    let measured: Vec<&Cell> = reparsed
        .cells
        .iter()
        .filter(|cell| !cell.samples.is_empty())
        .collect();
    assert_eq!(measured.len(), 1);
    assert_eq!(measured[0].samples.len(), 2);
    assert_eq!(reparsed.cells.len(), 36);
}

/// ATTR-01: direct construction and deserialization enforce the same identity.
#[test]
fn empty_identity_fields_are_rejected_on_record_and_parse() {
    for field in [
        "path",
        "owner",
        "version",
        "backend",
        "durability",
        "hardware",
        "corpus.id",
    ] {
        let mut invalid = sample(0, 10);
        let text = match field {
            "path" => &mut invalid.path,
            "owner" => &mut invalid.owner,
            "version" => &mut invalid.identity.version,
            "backend" => &mut invalid.identity.backend,
            "durability" => &mut invalid.identity.durability,
            "hardware" => &mut invalid.identity.hardware,
            _ => &mut invalid.identity.corpus.as_mut().expect("corpus").id,
        };
        *text = " \t".into();
        let mut ledger = Ledger::parse(LEDGER_TOML).expect("ledger");
        assert_eq!(
            ledger.record(CELL, invalid.clone()),
            Err(EvidenceError::MissingIdentityField(field))
        );
        ledger.cells[0].samples.push(invalid);
        assert_eq!(
            Ledger::parse(&ledger.render().expect("serialize invalid fixture")),
            Err(EvidenceError::MissingIdentityField(field))
        );
    }
}

/// ATTR-01: a hexadecimal digest cannot contain a numeric sign.
#[test]
fn signed_pairs_are_not_hexadecimal_digests() {
    assert!("+1".repeat(32).parse::<Sha256Hex>().is_err());
}

/// ATTR-01: aggregation cannot launder invalid identities or mix interval kinds.
#[test]
fn aggregation_validates_both_inputs_and_interval_kind() {
    let left = sample(0, 10);
    let mut right = sample(10, 20);
    right.interval.kind = IntervalKind::Outside;
    assert_eq!(left.sum(&right), Err(EvidenceError::MismatchedTreatment));
    right.interval.kind = IntervalKind::Inside;
    right.identity.version.clear();
    assert_eq!(
        left.sum(&right),
        Err(EvidenceError::MissingIdentityField("version"))
    );
    right = sample(10, 20);
    right.interval.end_ns = 0;
    assert_eq!(
        left.sum(&right),
        Err(EvidenceError::InvertedInterval(right.interval))
    );
}
