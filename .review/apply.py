#!/usr/bin/env python3
"""Prepare reviewed edits on a clean checkout; this helper never enters the PR."""
import re
import subprocess
import sys
import textwrap
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve()
assert not subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT).strip()
extra_guides = [str(p.relative_to(ROOT)) for p in ROOT.rglob('AGENTS.md') if p != ROOT / 'AGENTS.md' and '.git' not in p.parts]
assert not extra_guides, f'Read additional agent guidelines before editing: {extra_guides}'
print('SOURCE_COMMIT=' + subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip())


def write(path, content):
    target = ROOT / path
    old = target.read_text() if target.exists() else ''
    if old != content:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
        print(f'{path}: {len(old.splitlines())} -> {len(content.splitlines())} lines')


def replace_once(text, before, after):
    assert text.count(before) == 1, f'Expected exactly one occurrence: {before[:100]!r}'
    return text.replace(before, after, 1)


# take_at already restricts a fault to its boundary. Repeated matches only
# obscure the invariant, and several lost-completion arms falsely returned Ok.
FAULT_MATCH = re.compile(r'(?m)^(?P<indent> *)return match fault \{\n(?P<body>[\s\S]*?)^(?P=indent)\};')
PARTIAL_ARM = re.compile(r'(?m)^(?P<indent> *)crate::PersistFault::PartialApply => \{\n(?P<body>[\s\S]*?)^(?P=indent)\},?')


def simplify_fault_match(match):
    indent, body = match.group('indent', 'body')
    faults = set(re.findall(r'crate::PersistFault::(\w+)', body))
    if faults in ({'FailSync', 'LostSync'}, {'FailFlush', 'LostFlush'}):
        return indent + 'return Err(fault.injected_error());'
    if faults == {'FailApply', 'LostApply', 'PartialApply'}:
        partial = PARTIAL_ARM.search(body)
        if partial is None:
            assert body.count('Err(fault.injected_error())') == 1
            return indent + 'return Err(fault.injected_error());'
        lines = textwrap.dedent(partial.group('body')).rstrip().splitlines()
        assert lines[-1] == 'Err(fault.injected_error())'
        staged = textwrap.indent('\n'.join(lines[:-1]).rstrip(), indent + '    ')
        return (indent + 'if fault == crate::PersistFault::PartialApply {\n' + staged
                + '\n' + indent + '}\n' + indent + 'return Err(fault.injected_error());')
    raise AssertionError(f'Unexpected persistence fault match: {faults}')


for backend in ('fjall', 'redb', 'rocksdb', 'mdbx'):
    path = f'crates/storage/src/{backend}_impl.rs'
    source = (ROOT / path).read_text()
    updated, count = FAULT_MATCH.subn(simplify_fault_match, source)
    print(f'{backend}: simplified {count} boundary matches')
    write(path, updated)

path = 'crates/storage/src/trait_.rs'
source = (ROOT / path).read_text()
for pattern, replacement in [
    (r'    /// Lost write at the apply boundary:[\s\S]*?    LostApply,',
     '    /// The apply step is lost. Returns `Err` without applying the batch:\n'
     '    /// even a deferred write must be visible before it reports success.\n'
     '    LostApply,'),
    (r'    /// Lost durability completion:[\s\S]*?    LostSync,',
     '    /// The durability completion is lost after the batch applies. Returns\n'
     '    /// `Err`: visibility does not establish durable completion. A reopen\n'
     '    /// may observe the complete old or complete new state, never a mix.\n'
     '    LostSync,'),
    (r'    /// Lost flush:[\s\S]*?    LostFlush,',
     '    /// The flush completion is lost. Returns `Err` without confirming\n'
     '    /// durability; earlier batches must still recover atomically.\n'
     '    LostFlush,'),
]:
    source, count = re.subn(pattern, replacement, source)
    assert count == 1, pattern
source = source.replace('Unarmed stores never consult the seam, and a fault armed',
                        'An unarmed slot leaves behavior unchanged, and a fault armed')
source = source.replace('Unarmed stores never\n    /// consult the slot.',
                        'An unarmed slot leaves behavior unchanged.')
write(path, source)

path = 'crates/consensus/src/block_view.rs'
source = (ROOT / path).read_text()
source = replace_once(source, '''        let count_len = u64::from(compact_size_len(len_u64(txs.len())));
        let mut stripped = HEADER_LEN.saturating_add(count_len);
        let mut total = HEADER_LEN.saturating_add(count_len);
        for tx in txs {
            stripped = stripped.saturating_add(len_u64(tx.base_size()));
            total = total.saturating_add(len_u64(tx.total_size()));
        }
        let weight = stripped.saturating_mul(3).saturating_add(total);''',
    '        let weight = Self::block_weight(txs);')
source = replace_once(source, '''    /// Weight-only callers must not pay for [`Self::from_txids`]'s identifier
    /// clone and Merkle walk. The arithmetic below matches [`Self::from_txids`]
    /// exactly; any change there must change here.''',
    '    /// Shared by weight-only validation and [`Self::from_txids`].')
write(path, source)

write('crates/storage/tests/overhaul_atomic_durability.rs', r'''//! Fault-injection regressions for docs/contracts/recovery.md, RCV-04.
//!
//! A reopen must recover the complete old or complete new multi-family state.
//! Reads must succeed, and lost apply/sync/flush boundaries cannot produce false
//! success receipts. These checks do not substitute for power-loss testing.

#![cfg(any(feature = "fjall", feature = "redb", feature = "rocksdb", feature = "mdbx"))]
#![expect(clippy::expect_used, reason = "test assertions")]

use bitcoin_rs_storage::{ColumnFamily, KvPair, KvStore, PersistFault, StorageError, WriteBatch, WriteCondition};
use std::path::Path;

type Image = Vec<Vec<KvPair>>;

const FAMILIES: [ColumnFamily; 3] = [
    ColumnFamily::TxConfirmed,
    ColumnFamily::Funding,
    ColumnFamily::Spending,
];
const FAULTS: [PersistFault; 7] = [
    PersistFault::FailApply,
    PersistFault::LostApply,
    PersistFault::PartialApply,
    PersistFault::FailSync,
    PersistFault::LostSync,
    PersistFault::FailFlush,
    PersistFault::LostFlush,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Route {
    Write,
    Deferred,
    Durable,
    Conditional,
    Flush,
}

impl Route {
    const fn confirms_durability(self) -> bool {
        matches!(self, Self::Durable | Self::Conditional | Self::Flush)
    }

    const fn must_report_fault(self, fault: PersistFault) -> bool {
        match fault {
            PersistFault::FailApply | PersistFault::LostApply | PersistFault::PartialApply => true,
            PersistFault::FailSync | PersistFault::LostSync => matches!(self, Self::Durable | Self::Conditional),
            PersistFault::FailFlush | PersistFault::LostFlush => matches!(self, Self::Flush),
        }
    }

    fn apply<S: KvStore>(self, store: &S, families: &[ColumnFamily]) -> Result<(), StorageError> {
        let batch = batch(store, families, b"new");
        match self {
            Self::Write => store.write(batch),
            Self::Deferred => store.write_deferred(batch),
            Self::Durable => store.write_durable(batch),
            Self::Conditional => store.write_durable_if(
                &[WriteCondition::Absent { cf: families[0], key: &[0xff; 12] }],
                batch,
            ).map(|committed| assert!(committed, "the known-absent guard must match")),
            Self::Flush => store.write_deferred(batch).and_then(|()| store.flush()),
        }
    }
}

fn key(index: usize) -> [u8; 12] {
    [u8::try_from(index).expect("fixture family index fits in a byte"); 12]
}

fn image(families: &[ColumnFamily], value: &[u8]) -> Image {
    (0..families.len()).map(|index| vec![(key(index).to_vec(), value.to_vec())]).collect()
}

fn batch<S: KvStore>(store: &S, families: &[ColumnFamily], value: &[u8]) -> S::WriteBatch {
    let mut batch = store.new_batch();
    for (index, cf) in families.iter().enumerate() {
        batch.put(*cf, &key(index), value);
    }
    batch
}

fn snapshot_all(store: &impl KvStore, families: &[ColumnFamily]) -> Image {
    families.iter().map(|cf| {
        store.iter_prefix(*cf, b"").expect("open family iterator")
            .collect::<Result<Vec<_>, _>>().expect("read every family row")
    }).collect()
}

fn assert_atomic(observed: &Image, old: &Image, new: &Image) {
    assert!(observed == old || observed == new, "cross-family or partial state: {observed:?}");
}

fn run_fault_matrix<S, F>(backend: &str, open: F, families: &[ColumnFamily])
where
    S: KvStore,
    F: Fn(&Path) -> Result<S, StorageError>,
{
    let old = image(families, b"old");
    let new = image(families, b"new");
    for route in [Route::Write, Route::Deferred, Route::Durable, Route::Conditional, Route::Flush] {
        for fault in FAULTS {
            let dir = tempfile::tempdir().expect("tempdir");
            let label = format!("{backend}/{route:?}/{fault:?}");
            let outcome = {
                let store = open(dir.path()).expect("open store");
                store.write_durable(batch(&store, families, b"old")).expect("seed durably");
                assert_eq!(snapshot_all(&store, families), old);
                store.arm_persist_fault(fault);
                if route == Route::Conditional {
                    let committed = store.write_durable_if(
                        &[WriteCondition::Equals { cf: families[0], key: &key(0), expected: b"foreign" }],
                        batch(&store, families, b"new"),
                    ).expect("a mismatch must not consume an armed fault");
                    assert!(!committed, "{label}: mismatched guard committed");
                    assert_eq!(snapshot_all(&store, families), old);
                }
                let outcome = route.apply(&store, families);
                let visible = snapshot_all(&store, families);
                assert_atomic(&visible, &old, &new);
                if outcome.is_ok() {
                    assert_eq!(visible, new, "{label}: successful write was not visible");
                }
                if route.must_report_fault(fault) {
                    assert!(outcome.is_err(), "{label}: false success receipt");
                }
                if matches!(fault, PersistFault::FailApply | PersistFault::LostApply | PersistFault::PartialApply) {
                    assert_eq!(visible, old, "{label}: failed apply changed visible state");
                }
                if route == Route::Conditional && matches!(fault, PersistFault::FailFlush | PersistFault::LostFlush) {
                    assert!(store.flush().is_err(), "{label}: a condition check consumed the flush fault");
                }
                outcome
            };
            let store = open(dir.path()).expect("reopen store");
            let recovered = snapshot_all(&store, families);
            assert_atomic(&recovered, &old, &new);
            if outcome.is_ok() && route.confirms_durability() {
                assert_eq!(recovered, new, "{label}: confirmed durable state was lost");
            }
            if matches!(fault, PersistFault::FailApply | PersistFault::LostApply | PersistFault::PartialApply) {
                assert_eq!(recovered, old, "{label}: aborted apply survived reopen");
            }
        }
    }
}

#[test]
#[cfg(feature = "fjall")]
fn fjall_injected_faults_never_mix_families() {
    run_fault_matrix("fjall", |path| bitcoin_rs_storage::FjallStore::open(path), &FAMILIES);
}

#[test]
#[cfg(feature = "redb")]
fn redb_injected_faults_never_mix_families() {
    run_fault_matrix("redb", |path| bitcoin_rs_storage::RedbStore::open(path), &FAMILIES);
}

#[test]
#[cfg(feature = "rocksdb")]
fn rocksdb_injected_faults_never_mix_families() {
    run_fault_matrix("rocksdb", |path| bitcoin_rs_storage::RocksDbStore::open(path), &FAMILIES);
}

#[test]
#[cfg(feature = "mdbx")]
fn mdbx_injected_faults_never_mix_families() {
    run_fault_matrix("mdbx", |path| bitcoin_rs_storage::MdbxStore::open(path), &FAMILIES);
}

#[test]
#[cfg(feature = "redb")]
fn redb_txindex_injected_faults_never_mix_families() {
    run_fault_matrix("redb-txindex", |path| bitcoin_rs_storage::open_redb_tx_index_store(path),
        &[ColumnFamily::UtxoMeta, ColumnFamily::TxConfirmed]);
}

#[test]
#[should_panic(expected = "cross-family or partial state")]
fn atomicity_assertion_rejects_cross_family_mix() {
    let old = image(&FAMILIES, b"old");
    let new = image(&FAMILIES, b"new");
    let mut mixed = old.clone();
    mixed[0].clone_from(&new[0]);
    assert_atomic(&mixed, &old, &new);
}

#[test]
#[cfg(feature = "fjall")]
fn fjall_snapshot_is_coherent_across_batch_commit() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = bitcoin_rs_storage::FjallStore::open(dir.path()).expect("open");
    store.write_durable(batch(&store, &FAMILIES, b"old")).expect("seed");
    let snapshot = store.snapshot().expect("snapshot");
    store.write(batch(&store, &FAMILIES, b"new")).expect("commit while snapshot held");
    for (index, cf) in FAMILIES.iter().enumerate() {
        assert_eq!(snapshot.get(*cf, &key(index)).expect("snapshot read"), Some(b"old".to_vec()));
    }
    assert_eq!(snapshot_all(&store, &FAMILIES), image(&FAMILIES, b"new"));
}
''')
