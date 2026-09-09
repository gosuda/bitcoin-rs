#!/usr/bin/env python3
"""Final reviewed edits; this helper stays on the temporary review branch."""
import sys
from pathlib import Path

root = Path(sys.argv[1]).resolve()

def replace(source, before, after, count=1):
    assert source.count(before) == count, (before[:100], source.count(before), count)
    return source.replace(before, after)

# Keep each backend factory's lifetime tied to its owned temporary directory.
# The opaque redb adapter may capture &Path under Rust 2024. No production API
# change or leaked directory is needed. Every case still restores a durable seed.
path = root / 'crates/storage/tests/overhaul_atomic_durability.rs'
source = path.read_text()
source = replace(source, 'use std::path::Path;\n', '')
source = replace(source, 'F: Fn(&Path) -> Result<S, StorageError>', 'F: Fn() -> Result<S, StorageError>')
source = replace(source, '            let dir = tempfile::tempdir().expect("tempdir");\n', '')
source = replace(source, 'let store = open(dir.path())', 'let store = open()', count=2)
for backend, store in [('fjall', 'FjallStore'), ('redb', 'RedbStore'), ('rocksdb', 'RocksDbStore'), ('mdbx', 'MdbxStore')]:
    source = replace(source,
        f'    run_fault_matrix("{backend}", |path| bitcoin_rs_storage::{store}::open(path), &FAMILIES);',
        f'    let dir = tempfile::tempdir().expect("tempdir");\n    run_fault_matrix("{backend}", || bitcoin_rs_storage::{store}::open(dir.path()), &FAMILIES);')
source = replace(source,
    '    run_fault_matrix("redb-txindex", |path| bitcoin_rs_storage::open_redb_tx_index_store(path.to_path_buf()),',
    '    let dir = tempfile::tempdir().expect("tempdir");\n    run_fault_matrix("redb-txindex", || bitcoin_rs_storage::open_redb_tx_index_store(dir.path()),')
path.write_text(source)

path = root / 'crates/node/src/metrics.rs'
source = path.read_text()
source = replace(source, '        if text.len() != 64 {', '''        if text.len() != 64
            || !text.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {''')
source = replace(source, '''            if text.bytes().any(|c| c.is_ascii_uppercase()) {
                return Err(malformed());
            }
''', '')
source = replace(source,
    '        self.start_ns < other.end_ns && other.start_ns < self.end_ns',
    '''        self.start_ns < self.end_ns
            && other.start_ns < other.end_ns
            && self.start_ns < other.end_ns
            && other.start_ns < self.end_ns''')
source = replace(source, '''        if self.identity.corpus.is_none() {
            return Err(EvidenceError::MissingCorpus);
        }
        self.interval.check()''', '''        let corpus = self.identity.corpus.as_ref().ok_or(EvidenceError::MissingCorpus)?;
        for (field, value) in [
            ("path", self.path.as_str()),
            ("owner", self.owner.as_str()),
            ("version", self.identity.version.as_str()),
            ("backend", self.identity.backend.as_str()),
            ("durability", self.identity.durability.as_str()),
            ("hardware", self.identity.hardware.as_str()),
            ("corpus.id", corpus.id.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(EvidenceError::EmptyField(field));
            }
        }
        self.interval.check()''')
source = replace(source, '''        if self.path != other.path || self.owner != other.owner || self.identity != other.identity {
            return Err(EvidenceError::MismatchedTreatment);
        }''', '''        self.check()?;
        other.check()?;
        if self.path != other.path
            || self.owner != other.owner
            || self.identity != other.identity
            || self.interval.kind != other.interval.kind
        {
            return Err(EvidenceError::MismatchedTreatment);
        }''')
source = replace(source, '''    MissingCorpus,
    /// An interval ended before it started.''', '''    MissingCorpus,
    /// A required identity or sample label was empty or only whitespace.
    #[error("evidence field {0} is empty")]
    EmptyField(&'static str),
    /// An interval ended before it started.''')
source = replace(source, '#[error("samples differ in path, owner or identity")]',
    '#[error("samples differ in path, owner, identity or interval kind")]')
source = replace(source, '''/// A digest is bytes, not a label: a placeholder such as "unmeasured" cannot
/// parse, so an identity is either real or absent.''',
    '/// Parsing validates the encoding, not the provenance of the hashed artifact.')
source = replace(source, '''/// A number without this record is a rumor: it cannot be matched against a
/// control cell or regenerated later.''',
    '/// Used to match samples to their artifact, configuration, and treatment.')
path.write_text(source)

path = root / 'bin/bitcoin-rs/tests/overhaul_evidence.rs'
source = path.read_text()
source += r'''

#[test]
fn every_evidence_entry_point_rejects_blank_required_fields() {
    for field in ["path", "owner", "version", "backend", "durability", "hardware", "corpus.id"] {
        for blank in ["", " \t\n", "\u{2003}"] {
            let mut invalid = sample(0, 10);
            let value = match field {
                "path" => &mut invalid.path,
                "owner" => &mut invalid.owner,
                "version" => &mut invalid.identity.version,
                "backend" => &mut invalid.identity.backend,
                "durability" => &mut invalid.identity.durability,
                "hardware" => &mut invalid.identity.hardware,
                "corpus.id" => &mut invalid.identity.corpus.as_mut().expect("fixture corpus").id,
                _ => unreachable!("fixed field list"),
            };
            *value = blank.into();
            let expected = EvidenceError::EmptyField(field);
            let mut ledger = Ledger::parse(LEDGER_TOML).expect("ledger");
            assert_eq!(ledger.record(CELL, invalid.clone()), Err(expected));
            assert!(matches!(invalid.sum(&sample(10, 20)), Err(EvidenceError::EmptyField(name)) if name == field));
            assert!(matches!(sample(10, 20).sum(&invalid), Err(EvidenceError::EmptyField(name)) if name == field));
            // Deserialization must validate too, not just the record method.
            ledger.cells[0].samples.push(invalid);
            let text = ledger.render().expect("render unchecked fixture");
            assert!(matches!(Ledger::parse(&text), Err(EvidenceError::EmptyField(name)) if name == field));
        }
    }
}

#[test]
fn summation_validates_both_inputs_and_interval_kinds() {
    let left = sample(0, 10);
    let right = sample(10, 20);
    let mut missing_corpus = right.clone();
    missing_corpus.identity.corpus = None;
    assert_eq!(left.sum(&missing_corpus), Err(EvidenceError::MissingCorpus));
    assert_eq!(missing_corpus.sum(&left), Err(EvidenceError::MissingCorpus));
    let mut inverted = right.clone();
    inverted.interval.end_ns = 0;
    assert!(matches!(left.sum(&inverted), Err(EvidenceError::InvertedInterval(_))));
    assert!(matches!(inverted.sum(&left), Err(EvidenceError::InvertedInterval(_))));
    for kind in [IntervalKind::Outside, IntervalKind::DomainDefined] {
        let mut other = right.clone();
        other.interval.kind = kind;
        assert_eq!(left.sum(&other), Err(EvidenceError::MismatchedTreatment));
    }
}

#[test]
fn empty_half_open_intervals_share_no_instants() {
    let outer = sample(0, 20);
    for offset in [0, 10, 20] {
        let empty = sample(offset, offset);
        assert!(!empty.interval.overlaps(outer.interval));
        assert!(!outer.interval.overlaps(empty.interval));
        assert!(!empty.interval.overlaps(empty.interval));
        assert_eq!(outer.sum(&empty).expect("empty interval is disjoint").elapsed_ns, 20);
    }
    assert!(!outer.interval.overlaps(sample(20, 30).interval));
    assert!(outer.interval.overlaps(sample(19, 30).interval));
}

#[test]
fn digest_parser_rejects_signed_pairs_and_non_hex_spellings() {
    for malformed in ["+0".repeat(32), "-0".repeat(32), "0 ".repeat(32), "g0".repeat(32), "é".repeat(32)] {
        assert!(malformed.parse::<Sha256Hex>().is_err(), "accepted {malformed:?}");
    }
    for digest in [Sha256Hex([0; 32]), Sha256Hex([0xab; 32]), Sha256Hex([0xff; 32])] {
        assert_eq!(digest.to_string().parse::<Sha256Hex>(), Ok(digest));
    }
}
'''
path.write_text(source)
print('Backend-local factories and all evidence entry points updated')
