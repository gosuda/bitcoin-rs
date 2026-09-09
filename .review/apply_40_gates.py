#!/usr/bin/env python3
"""Review-only preparation. No helper or scratch workflow enters the PR."""
import hashlib
import sys
import urllib.request
from pathlib import Path

root = Path(sys.argv[1]).resolve()

def replace(source, before, after, count=1):
    assert source.count(before) == count, (before[:100], source.count(before), count)
    return source.replace(before, after)

# Keep the inventory gate, but validate the same typed histories as the writer.
path = root / 'bin/bitcoin-rs/tests/gates/g18_hot_path_ledger.rs'
source = path.read_text()
source = replace(source, '#[derive(Debug, Deserialize)]\nstruct Ledger {',
    '#[derive(Debug, Deserialize)]\n#[serde(deny_unknown_fields)]\nstruct Ledger {')
source = replace(source, '    forbidden_probes: Vec<ForbiddenProbe>,',
    '    forbidden_probes: Vec<ForbiddenProbe>,\n    cells: Vec<bitcoin_rs_node::metrics::Cell>,')
source = replace(source, '    toml::from_str(&text).unwrap_or_else(|error| {\n        panic!("parse {LEDGER}: {error}");\n    })',
    '    parse_ledger(&text).unwrap_or_else(|error| {\n        panic!("parse {LEDGER}: {error}");\n    })')
source += r'''

fn parse_ledger(text: &str) -> Result<Ledger, String> {
    bitcoin_rs_node::metrics::Ledger::parse(text).map_err(|error| error.to_string())?;
    let ledger: Ledger = toml::from_str(text).map_err(|error| error.to_string())?;
    let mut expected = BTreeSet::new();
    for domain in &ledger.matrix.domains {
        for corpus in &ledger.matrix.corpora {
            for arch in &ledger.matrix.archs {
                for backend in &ledger.matrix.backends {
                    expected.insert(format!("{domain}.{corpus}.{arch}.{backend}"));
                }
            }
        }
    }
    let observed: BTreeSet<_> = ledger.cells.iter().map(|cell| cell.id.clone()).collect();
    if expected.len() != CELL_COUNT || observed != expected || ledger.cells.len() != CELL_COUNT {
        return Err("cell histories must name every matrix cell exactly once".into());
    }
    Ok(ledger)
}

#[test]
fn cell_histories_match_the_frozen_matrix_exactly() {
    let ledger = load_ledger();
    assert_eq!(ledger.cells.len(), CELL_COUNT);
}

#[test]
fn gate_rejects_missing_duplicate_and_unknown_cell_histories() {
    let text = std::fs::read_to_string(workspace_file(LEDGER)).expect("ledger");
    let original = bitcoin_rs_node::metrics::Ledger::parse(&text).expect("valid histories");
    for mutation in 0..4 {
        let mut ledger = original.clone();
        match mutation {
            0 => { ledger.cells.clear(); }
            1 => { ledger.cells.pop(); }
            2 => {
                let duplicate = ledger.cells.first().expect("first cell").clone();
                *ledger.cells.last_mut().expect("last cell") = duplicate;
            }
            3 => { ledger.cells.first_mut().expect("first cell").id = "offline.unknown.x86_64.fjall".into(); }
            _ => unreachable!("fixed mutation set"),
        }
        assert!(parse_ledger(&ledger.render().expect("render fixture")).is_err());
    }
    let mut value: toml::Value = toml::from_str(&text).expect("TOML");
    value.as_table_mut().expect("root table").remove("cells");
    assert!(parse_ledger(&toml::to_string(&value).expect("render missing cells")).is_err());
}

#[test]
fn gate_rejects_malformed_samples_and_unknown_fields() {
    let text = std::fs::read_to_string(workspace_file(LEDGER)).expect("ledger");
    let mut value: toml::Value = toml::from_str(&text).expect("TOML");
    let cell = value.get_mut("cells").expect("cells").as_array_mut().expect("cell array")
        .first_mut().expect("first cell").as_table_mut().expect("cell table");
    cell.insert("samples".into(), toml::Value::Array(vec![toml::Value::Table(toml::map::Map::new())]));
    assert!(parse_ledger(&toml::to_string(&value).expect("malformed sample fixture")).is_err());
    let unknown = format!("misspelled_samples = []\n{text}");
    assert!(parse_ledger(&unknown).is_err());
}
'''
path.write_text(source)

# Drain both child pipes continuously, but retain only a bounded diagnostic tail.
path = root / 'bin/bitcoin-rs/tests/gates/g20_formal_models.rs'
source = path.read_text()
source = replace(source, '''    let out_thread = thread::spawn(move || {
        let mut buf = Vec::new();
        let mut reader = stdout_handle;
        let _ = reader.read_to_end(&mut buf).ok();
        buf
    });
    let err_thread = thread::spawn(move || {
        let mut buf = Vec::new();
        let mut reader = stderr_handle;
        let _ = reader.read_to_end(&mut buf).ok();
        buf
    });''', '''    let out_thread = thread::spawn(move || capture_tail(stdout_handle));
    let err_thread = thread::spawn(move || capture_tail(stderr_handle));''')
source = replace(source, '    let stdout = out_thread.join().expect("stdout reader");',
    '    let stdout = out_thread.join().expect("stdout reader").expect("read child stdout");')
source = replace(source, '    let stderr = err_thread.join().expect("stderr reader");',
    '    let stderr = err_thread.join().expect("stderr reader").expect("read child stderr");')
source += r'''

const MAX_CAPTURE_BYTES: usize = 1024 * 1024;
const TRUNCATED_OUTPUT: &[u8] = b"[earlier process output truncated]\n";

fn capture_tail(mut reader: impl Read) -> std::io::Result<Vec<u8>> {
    let mut tail = std::collections::VecDeque::with_capacity(MAX_CAPTURE_BYTES);
    let mut chunk = [0_u8; 8192];
    let mut truncated = false;
    loop {
        let count = match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(count) => count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        let discarded = (tail.len() + count).saturating_sub(MAX_CAPTURE_BYTES);
        if discarded != 0 {
            tail.drain(..discarded);
            truncated = true;
        }
        tail.extend(chunk.get(..count).expect("read fits buffer"));
    }
    let mut output = if truncated { TRUNCATED_OUTPUT.to_vec() } else { Vec::new() };
    output.extend(tail);
    Ok(output)
}

#[test]
fn bounded_capture_preserves_short_and_exact_output() {
    for bytes in [Vec::new(), b"diagnostic\n".to_vec(), vec![b'x'; MAX_CAPTURE_BYTES]] {
        assert_eq!(capture_tail(bytes.as_slice()).expect("capture"), bytes);
    }
}

#[test]
fn bounded_capture_drains_excess_and_retains_the_diagnostic_tail() {
    let mut bytes = vec![b'x'; 3 * MAX_CAPTURE_BYTES];
    bytes.extend_from_slice(b"final diagnostic\n");
    let captured = capture_tail(bytes.as_slice()).expect("capture");
    assert_eq!(captured.len(), MAX_CAPTURE_BYTES + TRUNCATED_OUTPUT.len());
    assert!(captured.starts_with(TRUNCATED_OUTPUT));
    assert!(captured.ends_with(b"final diagnostic\n"));
    assert_eq!(captured.get(TRUNCATED_OUTPUT.len()..).expect("tail"),
               bytes.get(bytes.len() - MAX_CAPTURE_BYTES..).expect("expected tail"));
}

#[test]
fn bounded_capture_retries_interrupts_and_propagates_read_errors() {
    struct FailsAfterInterrupt(bool);
    impl Read for FailsAfterInterrupt {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            if std::mem::replace(&mut self.0, false) {
                Err(std::io::ErrorKind::Interrupted.into())
            } else {
                Err(std::io::Error::other("injected read failure"))
            }
        }
    }
    assert_eq!(capture_tail(FailsAfterInterrupt(true)).expect_err("read error").kind(),
               std::io::ErrorKind::Other);
}
'''
path.write_text(source)

# Restore the reviewed, implemented baseline rather than relabel planned files
# as proof. The exact upstream document was read before preparing this edit.
path = root / 'docs/contracts/recovery.md'
old = path.read_bytes()
old_sha = hashlib.sha1(b'blob ' + str(len(old)).encode() + b'\0' + old).hexdigest()
assert old_sha == 'a441ad66b152275ce5f6c3196734643473839e0e', 'Re-review concurrent recovery edits'
url = 'https://raw.githubusercontent.com/gosuda/bitcoin-rs/57532f2d4b18d48dac7bb7d450226961f2988bde/docs/contracts/recovery.md'
with urllib.request.urlopen(url, timeout=20) as response:
    baseline = response.read()
assert hashlib.sha1(b'blob ' + str(len(baseline)).encode() + b'\0' + baseline).hexdigest() == 'b4b6f87e4dc674d972233150d7702c4215bdaed9'
source = baseline.decode()
source = replace(source, '\n## Proven by\n', r'''
### `RCV-05`: Storage batch completion

`KvStore` in `crates/storage/src/trait_.rs` owns visibility and durability
receipts. `write_durable` and a matching `write_durable_if` confirm durable
completion; `flush` confirms earlier deferred writes. A rejected condition
changes no rows. A lost apply, sync, or flush completion returns an error,
not a false success receipt. An error after application may leave the whole
batch visible; callers must not infer that an error rolled it back.

The Fjall, redb, RocksDB, and MDBX adapters preserve batch atomicity across
families. `crates/storage/tests/overhaul_atomic_durability.rs` tests whole-old
or whole-new state, successful durable receipts, rejected conditions, and
read-error propagation through injected faults and clean reopen. These
checks do not establish actual power-loss behavior or a node-wide atomic
commit of coins, bodies, undo, and the published tip.

### `RCV-06`: Incremental grouped-coin wrapper

`crates/utxo/src/set/persistent.rs` serializes cache reload, mutation,
persistence, and eviction. Stored rows must decode, contain live outputs,
and match the complete transaction identity. Read and ledger failures are
errors, not missing coins or partial counts. A resident-record miss can
reload from storage; a missing output in a resident record does not refill it.

A failed mutation quarantines the wrapper: reads, writes, ledger scans, and
flush return `RecoveryRequired` until the caller discards the instance and
recovers externally. It does not roll back shards or implement node-wide
recovery. Failed flushes retain pending-write pins and may be retried. A
successful flush releases pins and reapplies the best-effort resident budget;
reads also reapply that budget. A no-op mutation does not flush earlier work.

This wrapper is not the node's recovery authority and does not replace its
checkpoint path. The durable-root owner and its formal promotion gates remain
unimplemented; candidate models are not evidence of production behavior.

## Proven by
''')
source += r'''
- `crates/storage/tests/overhaul_atomic_durability.rs`: the five backend/adapter
  fault matrices, `atomicity_assertion_rejects_cross_family_mix`, and
  `fjall_snapshot_is_coherent_across_batch_commit` (`RCV-05`).
- `crates/utxo/tests/overhaul_persistent_coins.rs`:
  `read_and_iterator_failures_are_not_absence_or_partial_ledgers`,
  `corrupt_rows_cannot_be_read_spent_or_overwritten`,
  `stored_full_identity_must_match_even_when_accelerators_collide`,
  `failed_mutations_quarantine_all_public_operations`,
  `refills_and_successful_flushes_reapply_the_resident_budget`,
  `missing_vout_in_a_resident_record_does_not_refill`, and
  `concurrent_partial_spends_preserve_siblings_and_store_cache_agreement`
  (`RCV-06`).
'''
path.write_text(source)

path = root / 'docs/contracts/README.md'
source = path.read_text()
lines = source.splitlines()
for index, line in enumerate(lines):
    if line.startswith('| [recovery.md]'):
        lines[index] = '| [recovery.md](recovery.md) | `RCV-01`–`RCV-06` | Current checkpoint/index recovery, storage batch receipts, and the fail-closed incremental coin wrapper | `crates/node`, `crates/storage`, `crates/utxo`, RPC capabilities | Named tests in [recovery.md](recovery.md#proven-by), including `overhaul_atomic_durability` and `overhaul_persistent_coins` |'
        break
else:
    raise AssertionError('Recovery index row missing')
path.write_text('\n'.join(lines) + '\n')

for relative, clause in [('crates/storage/tests/overhaul_atomic_durability.rs', 'RCV-05'),
                          ('crates/utxo/src/set/persistent.rs', 'RCV-06'),
                          ('crates/utxo/tests/overhaul_persistent_coins.rs', 'RCV-06')]:
    path = root / relative
    source = path.read_text()
    source = source.replace('RCV-04', clause)
    path.write_text(source)
print('G18 typed histories, bounded G20 diagnostics, and current recovery contract prepared')
